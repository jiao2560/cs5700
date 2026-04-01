"""
security.py — Phase 2 Security Layer for SRFT

Provides:
- PSK loading / generation
- Handshake protocol (ClientHello / ServerHello) with HMAC-SHA256
- Session key derivation via HKDF-SHA256
- AEAD encryption / decryption (AES-256-GCM)
- Replay detection
- SHA-256 file/byte hashing

Dependencies:
    pip install cryptography
"""

import os
import struct
import hmac
import hashlib
import threading
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256 as HKDF_SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import (
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    FLAG_DATA,
    FLAG_DATA_LAST,
    FLAG_FIN,
)

# ── Constants ────────────────────────────────────────────────────────────
NONCE_SIZE = 16  # Client / server handshake nonce (bytes)
SESSION_ID_SIZE = 8  # Session ID (bytes)
HMAC_SIZE = 32  # HMAC-SHA256 output (bytes)
KEY_SIZE = 32  # AES-256 key (bytes)
PROTOCOL_VERSION = struct.pack("!H", 1)  # v1.0

DEFAULT_PSK_PATH = "psk.key"


# ── PSK Management ───────────────────────────────────────────────────────

def load_psk(filepath=DEFAULT_PSK_PATH):
    """
    Load a 32-byte pre-shared key from a hex-encoded file.
    Raises ValueError if the key is the wrong length.
    """
    with open(filepath, "r") as f:
        hex_key = f.read().strip()
    psk = bytes.fromhex(hex_key)
    if len(psk) != KEY_SIZE:
        raise ValueError(f"PSK must be {KEY_SIZE} bytes, got {len(psk)}")
    return psk


def generate_psk(filepath=DEFAULT_PSK_PATH):
    """Generate a random 32-byte PSK and write it hex-encoded to *filepath*."""
    psk = os.urandom(KEY_SIZE)
    with open(filepath, "w") as f:
        f.write(psk.hex())
    print(f"[PSK] Generated new PSK → {filepath}")
    return psk


# ── HMAC Helpers ─────────────────────────────────────────────────────────

def compute_hmac(psk, data):
    """Compute HMAC-SHA256 over *data* keyed with *psk*."""
    return hmac.new(psk, data, hashlib.sha256).digest()


def verify_hmac(psk, data, expected_mac):
    """Constant-time HMAC-SHA256 verification."""
    return hmac.compare_digest(compute_hmac(psk, data), expected_mac)


# ── Key Derivation ───────────────────────────────────────────────────────

def derive_session_key(psk, client_nonce, server_nonce):
    """
    Derive a 32-byte encryption key using HKDF-SHA256.
    salt  = client_nonce || server_nonce
    info  = b"srft-session-key"
    """
    hkdf = HKDF(
        algorithm=HKDF_SHA256(),
        length=KEY_SIZE,
        salt=client_nonce + server_nonce,
        info=b"srft-session-key",
    )
    return hkdf.derive(psk)


# ── Handshake Message Builders / Parsers ─────────────────────────────────

def build_client_hello(psk):
    """
    Build a ClientHello payload.

    Layout:  client_nonce (16) | protocol_version (2) | HMAC (32)
    Returns: (payload_bytes, client_nonce)
    """
    client_nonce = os.urandom(NONCE_SIZE)
    data = client_nonce + PROTOCOL_VERSION
    mac = compute_hmac(psk, data)
    return data + mac, client_nonce


def parse_client_hello(payload, psk):
    """
    Verify and parse a ClientHello payload.
    Returns client_nonce on success, None on HMAC failure.
    """
    expected_len = NONCE_SIZE + 2 + HMAC_SIZE  # 50
    if len(payload) != expected_len:
        return None
    data = payload[: NONCE_SIZE + 2]
    received_mac = payload[NONCE_SIZE + 2 :]
    if not verify_hmac(psk, data, received_mac):
        return None
    return payload[:NONCE_SIZE]


def build_server_hello(psk, client_nonce):
    """
    Build a ServerHello payload.

    Layout:  server_nonce (16) | session_id (8) | HMAC (32)
    HMAC covers: server_nonce | session_id | client_nonce
    Returns: (payload_bytes, server_nonce, session_id)
    """
    server_nonce = os.urandom(NONCE_SIZE)
    session_id = os.urandom(SESSION_ID_SIZE)
    mac_input = server_nonce + session_id + client_nonce
    mac = compute_hmac(psk, mac_input)
    return server_nonce + session_id + mac, server_nonce, session_id


def parse_server_hello(payload, psk, client_nonce):
    """
    Verify and parse a ServerHello payload.
    Returns (server_nonce, session_id) on success, (None, None) on failure.
    """
    expected_len = NONCE_SIZE + SESSION_ID_SIZE + HMAC_SIZE  # 56
    if len(payload) != expected_len:
        return None, None
    server_nonce = payload[:NONCE_SIZE]
    session_id = payload[NONCE_SIZE : NONCE_SIZE + SESSION_ID_SIZE]
    received_mac = payload[NONCE_SIZE + SESSION_ID_SIZE :]
    mac_input = server_nonce + session_id + client_nonce
    if not verify_hmac(psk, mac_input, received_mac):
        return None, None
    return server_nonce, session_id


# ── Security Context (per-session state) ─────────────────────────────────

class SecurityContext:
    """
    Holds per-session encryption state and exposes encrypt / decrypt helpers.

    Parameters
    ----------
    enc_key   : bytes   – 32-byte AES-256 key (from HKDF)
    session_id: bytes   – 8-byte session identifier
    direction : int     – 0 = server (sends DATA), 1 = client (sends ACKs)
    """

    def __init__(self, enc_key, session_id, direction):
        self.enc_key = enc_key
        self.session_id = session_id
        self.direction = direction
        self.aesgcm = AESGCM(enc_key)

        # Monotonic counter → guarantees unique GCM nonce per direction
        self.send_counter = 0
        self._counter_lock = threading.Lock()

        # Replay detection sets
        self._accepted_data_seqs = set()
        self._accepted_fin = False
        self._replay_lock = threading.Lock()

        # Counters for the Phase 2 report
        self.aead_failures = 0
        self.replay_drops = 0

    # ── nonce / AAD construction ──────────────────────────────────────

    def _next_nonce(self):
        """
        Return a unique 12-byte GCM nonce.
        Layout: direction (1 byte) | padding (3 bytes) | counter (8 bytes)
        """
        with self._counter_lock:
            nonce = struct.pack("!B3xQ", self.direction, self.send_counter)
            self.send_counter += 1
        return nonce

    @staticmethod
    def build_aad(session_id, seq_num, ack_num, flags):
        """Pack the Additional Authenticated Data (AAD) that binds metadata."""
        return struct.pack("!8sIIB", session_id, seq_num, ack_num, flags)

    # ── encrypt / decrypt ─────────────────────────────────────────────

    def encrypt(self, plaintext, seq_num, ack_num, flags):
        """
        AES-256-GCM encrypt.

        Returns: nonce (12 B) || ciphertext || tag (16 B)
        """
        nonce = self._next_nonce()
        aad = self.build_aad(self.session_id, seq_num, ack_num, flags)
        ct_and_tag = self.aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ct_and_tag

    def decrypt(self, encrypted_payload, seq_num, ack_num, flags):
        """
        AES-256-GCM decrypt + verify.

        Returns plaintext bytes on success, None on any failure.
        """
        min_len = GCM_NONCE_SIZE + GCM_TAG_SIZE
        if len(encrypted_payload) < min_len:
            self.aead_failures += 1
            return None
        nonce = encrypted_payload[:GCM_NONCE_SIZE]
        ct_and_tag = encrypted_payload[GCM_NONCE_SIZE:]
        aad = self.build_aad(self.session_id, seq_num, ack_num, flags)
        try:
            return self.aesgcm.decrypt(nonce, ct_and_tag, aad)
        except Exception:
            self.aead_failures += 1
            return None

    # ── replay protection ─────────────────────────────────────────────

    def check_replay(self, seq_num, flags):
        """
        Return True (= drop) if this DATA/FIN packet is a replay.
        Automatically records the seq once accepted.
        """
        with self._replay_lock:
            if flags in (FLAG_DATA, FLAG_DATA_LAST):
                if seq_num in self._accepted_data_seqs:
                    self.replay_drops += 1
                    return True
                self._accepted_data_seqs.add(seq_num)
                return False
            if flags == FLAG_FIN:
                if self._accepted_fin:
                    self.replay_drops += 1
                    return True
                self._accepted_fin = True
                return False
        return False


# ── SHA-256 Utilities ────────────────────────────────────────────────────

def compute_file_sha256(filepath):
    """Stream-hash a file with SHA-256 and return the 32-byte digest."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.digest()


def compute_bytes_sha256(data):
    """SHA-256 digest over raw bytes."""
    return hashlib.sha256(data).digest()


# ── CLI helper ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "generate":
        path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PSK_PATH
        generate_psk(path)
    else:
        print("Usage: python security.py generate [path]")
        print("  Generates a random 32-byte PSK and writes it to the given file.")