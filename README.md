# SRFT Project - Person A Deliverable

## Overview

This part implements the lowest layer of the SRFT project using raw UDP sockets in Python.

## Completed Work

- Built raw IPv4 headers manually
- Built raw UDP headers manually
- Implemented UDP checksum calculation
- Implemented packet construction with:
  - IP header
  - UDP header
  - payload
- Implemented packet parsing for incoming raw packets
- Built a raw UDP client
- Built a raw UDP server
- Verified local packet sending and receiving in WSL/Ubuntu

## Main Files

- `config.py`: shared constants and configuration
- `packet.py`: packet construction and parsing functions
- `test_packet.py`: local test for packet build/parse
- `SRFT_UDPClient.py`: sends raw UDP packets
- `SRFT_UDPServer.py`: receives and parses raw UDP packets

## Core Functions

- `compute_checksum(data)`
- `build_ip_header(src_ip, dst_ip, total_length)`
- `build_udp_header(src_port, dst_port, payload)`
- `build_packet(src_ip, dst_ip, src_port, dst_port, payload)`
- `parse_packet(raw_bytes)`

## Test Result

The client successfully sent a raw UDP packet, and the server successfully received and parsed it.

Example parsed output:

- Source IP: `127.0.0.1`
- Destination IP: `127.0.0.1`
- Source Port: `8888`
- Destination Port: `9999`
- Payload: `b'hello from client'`

---

## Person B - Reliable File Transfer (Phase 1)

### Overview

This part implements reliable file transfer on top of Person A's raw socket foundation using a sliding window protocol with cumulative acknowledgments.

### Completed Work

- Created `reliable_transfer.py` with `Sender` (server) and `Receiver` (client) classes
- Implemented sliding window protocol (window size = 4)
- Added sequence numbers to data packets for ordering and duplicate detection
- Implemented cumulative acknowledgments (ACK = next expected sequence number)
- Added timeout (1.0s) and retransmission for lost packets
- Split files into chunks, send with sequence numbers, reassemble at receiver
- Added multithreading: separate send and receive threads for concurrency
- Implemented MD5 hash verification (server sends hash in FIN, client verifies)
- Generate output report `output.txt` with transfer statistics

### Main Files

- `reliable_transfer.py`: `Sender` and `Receiver` classes for reliable transfer
- `transfer_base.py`: shared base class with receive loop and state management
- `app_packet.py`: application-layer packet format (seq, ack, flags, payload)

### Core Functions

- `Sender.listen_and_serve()`: start server threads to handle file requests
- `Receiver.request_file(filename, output_path)`: client entry point to request a file
- `Packet.get_req_packet()`, `get_data_packet()`, `get_ack_packet()`, `get_fin_packet()`: create application packets
- `ReliableTransferBase.sliding_window_rcv()`: base receive loop that dispatches packets

### Protocol Flags (defined in `config.py`)

- `FLAG_REQ` (3): client requests a file (payload = filename)
- `FLAG_DATA` (0): server sends file chunk
- `FLAG_DATA_LAST` (4): last file chunk
- `FLAG_ACK` (1): client acknowledges received data (cumulative ACK)
- `FLAG_FIN` (2): server signals transfer complete (payload = MD5 hash)

### Usage Example

See `tests/test_integration.py` for complete working examples:

```python
import socket
from reliable_transfer import Sender, Receiver
from config import SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT

# Server (sender)
sender_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
sender_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sender = Sender(sender_sock, CLIENT_IP, CLIENT_PORT)
sender.listen_and_serve()

# Client (receiver)
receiver_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
receiver_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
receiver = Receiver(receiver_sock, SERVER_IP, SERVER_PORT)
receiver.request_file("test.txt", "received.txt")
```

### Test Results

- **Unit tests**: `tests/test_reliable_transfer.py` (22 tests, all passing)
- **Integration tests**: `tests/test_integration.py` (6 tests, all passing with root privileges)
  - Basic file transfer
  - Large file transfer (multiple chunks)
  - Consecutive transfers
  - Empty file handling
  - Error handling (non‑existent files)
  - Failed transfer recovery




## Person C — Secure Reliable File Transfer (Phase 2)

### Overview

This part adds a full security layer on top of Person B's reliable file transfer, providing confidentiality, integrity, authentication, and replay protection. All data in transit is encrypted using AES-256-GCM with per-session keys derived from a pre-shared key (PSK) via HKDF-SHA256. A custom handshake protocol (ClientHello / ServerHello) authenticates both parties before any file data is exchanged. Every packet is protected with Authenticated Encryption with Associated Data (AEAD), and a SHA-256 end-to-end file digest verifies the entire transfer.

### Completed Work

* Created `security.py` with all cryptographic primitives and the `SecurityContext` class
* Implemented PSK management: loading from hex-encoded `psk.key` file, generation via CLI
* Implemented handshake protocol:
  * `ClientHello`: client generates a random 16-byte nonce, sends it with protocol version and HMAC-SHA256 (keyed with PSK)
  * `ServerHello`: server verifies client HMAC, generates its own 16-byte nonce and 8-byte session ID, replies with HMAC-SHA256
  * If either HMAC verification fails, the connection is rejected — no file transfer occurs
* Implemented HKDF-SHA256 key derivation: derives a 32-byte `enc_key` from PSK + client_nonce + server_nonce
* Implemented AES-256-GCM authenticated encryption on all packets:
  * Every DATA packet payload is encrypted before sending
  * Every ACK packet payload is encrypted before sending
  * Every FIN packet payload (SHA-256 digest) is encrypted before sending
  * Every REQ packet payload (filename) is encrypted before sending
* Implemented AAD (Additional Authenticated Data) binding on every packet:
  * AAD includes: `session_id` (8 bytes), `sequence_number` (4 bytes), `ack_number` (4 bytes), `flags` (1 byte)
  * Attackers cannot modify any metadata field without detection — decryption will fail
* Implemented unique GCM nonce generation per packet:
  * Layout: direction byte (1) + padding (3) + monotonic counter (8) = 12 bytes
  * Direction byte (0 = server, 1 = client) prevents nonce collision between sender and receiver
* Implemented replay protection:
  * Receiver tracks a set of accepted DATA sequence numbers
  * Duplicate/replayed DATA packets are detected and dropped (counter incremented)
  * FIN replay is also detected
  * Retransmitted packets (from server due to lost ACK) are detected as replays but still trigger a re-ACK so the sender window can advance
* Implemented SHA-256 end-to-end file verification:
  * Server computes SHA-256 of the original file and sends it in the encrypted FIN packet
  * Client computes SHA-256 of the reassembled file and compares digests
  * Client sends the match result (1 byte) back to the server in the encrypted FIN-ACK
  * Transfer is only "successful" if digests match
* Created `secure_transfer.py` with `SecureSender` and `SecureReceiver` classes that extend Person B's `Sender` and `Receiver`
* Updated `config.py` with Phase 2 flags (`FLAG_CLIENT_HELLO`, `FLAG_SERVER_HELLO`) and security constants
* Updated `SRFT_UDPServer.py` and `SRFT_UDPClient.py` with proper CLI entry points for Phase 2
* Created `test_phase2.py` with 6 automated tests (all passing)

### Main Files

* `security.py`: all cryptographic functions and the `SecurityContext` class
* `secure_transfer.py`: `SecureSender` (server) and `SecureReceiver` (client) classes
* `psk.key`: pre-shared key file (32-byte key, hex-encoded)
* `config.py` (updated): added `FLAG_CLIENT_HELLO`, `FLAG_SERVER_HELLO`, `GCM_NONCE_SIZE`, `GCM_TAG_SIZE`, `SECURITY_OVERHEAD`, `HANDSHAKE_TIMEOUT`, `HANDSHAKE_MAX_RETRIES`
* `SRFT_UDPServer.py` (updated): server entry point with PSK loading and `--psk` flag
* `SRFT_UDPClient.py` (updated): client entry point with PSK loading, `--psk` flag, and `--timeout` flag
* `test_phase2.py`: automated Phase 2 test suite

### Core Functions and Classes

**`security.py`**

* `load_psk(filepath)`: load a 32-byte PSK from a hex-encoded file
* `generate_psk(filepath)`: generate a random PSK and write to file
* `compute_hmac(psk, data)`: compute HMAC-SHA256
* `verify_hmac(psk, data, expected_mac)`: constant-time HMAC verification
* `derive_session_key(psk, client_nonce, server_nonce)`: HKDF-SHA256 key derivation → 32-byte `enc_key`
* `build_client_hello(psk)`: build ClientHello payload (nonce + version + HMAC)
* `parse_client_hello(payload, psk)`: verify and parse ClientHello
* `build_server_hello(psk, client_nonce)`: build ServerHello payload (nonce + session_id + HMAC)
* `parse_server_hello(payload, psk, client_nonce)`: verify and parse ServerHello
* `compute_file_sha256(filepath)`: stream-hash a file with SHA-256
* `compute_bytes_sha256(data)`: SHA-256 digest over raw bytes

**`SecurityContext` class (in `security.py`)**

* `SecurityContext(enc_key, session_id, direction)`: per-session encryption state
* `encrypt(plaintext, seq_num, ack_num, flags)`: AES-256-GCM encrypt with AAD, returns `nonce || ciphertext || tag`
* `decrypt(encrypted_payload, seq_num, ack_num, flags)`: AES-256-GCM decrypt + verify, returns plaintext or `None` on failure
* `check_replay(seq_num, flags)`: returns `True` if packet is a replay (and increments counter)
* `build_aad(session_id, seq_num, ack_num, flags)`: pack the AAD bytes

**`secure_transfer.py`**

* `SecureSender(sock, dest_ip, dest_port, psk)`: extends `Sender` with handshake, encryption, and Phase 2 reporting
* `SecureReceiver(sock, dest_ip, dest_port, psk)`: extends `Receiver` with handshake, decryption, replay detection, and SHA-256 verification

### Protocol Flags Added (defined in `config.py`)

* `FLAG_CLIENT_HELLO` (5): handshake initiation from client (payload = nonce + version + HMAC)
* `FLAG_SERVER_HELLO` (6): handshake response from server (payload = nonce + session_id + HMAC)

### Security Protocol Flow

```
Client                                          Server
  │                                                │
  │──── ClientHello ──────────────────────────────▶│
  │     (client_nonce + version + HMAC)            │
  │                                                │  verify HMAC
  │◀──── ServerHello ─────────────────────────────│
  │      (server_nonce + session_id + HMAC)        │
  │  verify HMAC                                   │
  │                                                │
  │  ── Both sides derive enc_key via HKDF ──      │
  │                                                │
  │──── Encrypted REQ (filename) ─────────────────▶│
  │                                                │  decrypt, read file
  │◀──── Encrypted DATA seq=0 ────────────────────│
  │──── Encrypted ACK ack=1 ──────────────────────▶│
  │◀──── Encrypted DATA seq=1 ────────────────────│
  │──── Encrypted ACK ack=2 ──────────────────────▶│
  │          ... (sliding window) ...              │
  │◀──── Encrypted DATA seq=N (LAST) ─────────────│
  │──── Encrypted ACK ack=N+1 ────────────────────▶│
  │                                                │
  │◀──── Encrypted FIN (SHA-256 digest) ──────────│
  │  verify SHA-256                                │
  │──── Encrypted FIN-ACK (match byte) ───────────▶│
  │                                                │  write output.txt
```

### Packet Encryption Details

Every packet payload is encrypted as:

```
[GCM Nonce (12 bytes)] [Ciphertext (variable)] [GCM Auth Tag (16 bytes)]
```

The AAD (Additional Authenticated Data) for every packet is:

```
[session_id (8 bytes)] [seq_num (4 bytes)] [ack_num (4 bytes)] [flags (1 byte)]
```

This means if an attacker modifies any of these fields, the GCM authentication tag verification fails and the packet is discarded.

### Dependencies

```
pip install cryptography
```

Uses `cryptography.hazmat.primitives.ciphers.aead.AESGCM` for AES-256-GCM and `cryptography.hazmat.primitives.kdf.hkdf.HKDF` for key derivation.

### Usage

**Generate a new PSK (optional — a default `psk.key` is provided):**

```bash
python3 security.py generate
python3 security.py generate /path/to/custom.key
```

**Run the server:**

```bash
sudo python3 SRFT_UDPServer.py
sudo python3 SRFT_UDPServer.py --psk /path/to/psk.key
```

**Run the client:**

```bash
sudo python3 SRFT_UDPClient.py /path/to/file.txt -o received.txt
sudo python3 SRFT_UDPClient.py /path/to/image.png -o received.png --psk /path/to/psk.key
```

### Test Results

* Automated test suite: `test_phase2.py` (6 tests, all passing with root privileges)
  * Small text file transfer (120 bytes) — basic encrypted transfer
  * Large text file transfer (~50KB) — multiple encrypted chunks with sliding window
  * Binary file transfer (~10KB) — non-text data with PNG-like header
  * Empty file transfer — edge case with zero-length payload
  * Wrong PSK rejection — handshake fails, no file transferred
  * Medium binary file transfer (~100KB) — stress test with random bytes

**Run the tests:**

```bash
sudo python3 test_phase2.py
```

**Sample test output:**

```
============================================================
  SRFT Phase 2 — Security Layer Tests
============================================================

✅  Test 1 — Small Text File
✅  Test 2 — Large Text File (multi-chunk)
✅  Test 3 — Binary File
✅  Test 4 — Empty File
✅  Test 5 — Wrong PSK (expect failure)
✅  Test 6 — Medium Binary File (100KB)

============================================================
  RESULTS: 6/6 tests passed
============================================================
  🎉 All tests passed! Phase 2 security layer is working.
```

**Sample Phase 2 output report (`output.txt`):**

```
Name of the transferred file: /path/to/test.txt
Size of the transferred file: 120 bytes
The number of packets sent from the server: 2
The number of retransmitted packets from the server: 0
The number of packets received from the client: 2
The time duration of the file transfer: 00:00:00
Security enabled (PSK + AEAD): Yes
Handshake status: Success
AEAD authentication failures (invalid packets dropped): 0
Replay drops (duplicate/out-of-window packets): 0
SHA-256 match: Yes
```