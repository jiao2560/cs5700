"""
secure_transfer.py — Phase 2 Secure Reliable File Transfer

SecureSender  (extends Sender)  — server side
SecureReceiver (extends Receiver) — client side

Adds: PSK handshake, AES-256-GCM AEAD on every packet, replay
detection, and SHA-256 end-to-end file verification.
"""

import socket
import hashlib
import threading
import time
from typing import Optional

from config import (
    SERVER_IP,
    SERVER_PORT,
    CLIENT_IP,
    CLIENT_PORT,
    MAX_PAYLOAD_SIZE,
    TIMEOUT,
    WINDOW_SIZE,
    FLAG_DATA,
    FLAG_DATA_LAST,
    FLAG_ACK,
    FLAG_FIN,
    FLAG_REQ,
    FLAG_CLIENT_HELLO,
    FLAG_SERVER_HELLO,
    SECURITY_OVERHEAD,
    HANDSHAKE_TIMEOUT,
    HANDSHAKE_MAX_RETRIES,
)
from packet import parse_packet
from app_packet import Packet, HEADER_SIZE
from reliable_transfer import Sender, Receiver
from security import (
    load_psk,
    build_client_hello,
    parse_client_hello,
    build_server_hello,
    parse_server_hello,
    derive_session_key,
    SecurityContext,
    compute_bytes_sha256,
    compute_file_sha256,
)


# ═══════════════════════════════════════════════════════════════════════════
#  SecureSender  (server)
# ═══════════════════════════════════════════════════════════════════════════

class SecureSender(Sender):
    """
    Server-side secure sender.

    Extends Sender with:
      - ClientHello verification + ServerHello response
      - AEAD encryption of every outgoing DATA / FIN packet
      - AEAD decryption + replay check on incoming ACKs
      - SHA-256 file digest in the FIN packet
      - Extended Phase 2 output report
    """

    def __init__(self, sock, dest_ip, dest_port, psk):
        super().__init__(sock, dest_ip, dest_port)
        self.psk = psk
        self.security_ctx: Optional[SecurityContext] = None
        self.handshake_status = "Pending"
        self.sha256_hash = b""
        self.sha256_match = None  # Set when client reports back

        # Cache the ServerHello raw packet for retransmit on duplicate ClientHello
        self._cached_sh_raw = None
        self._cached_sh_addr = None

    # ── receive loop override (adds handshake dispatch) ───────────────

    def sliding_window_rcv(self):
        """Extended receive loop that also handles CLIENT_HELLO."""
        print("[SERVER] secure sliding_window_rcv thread started")
        while self.running:
            try:
                data, _ = self.sock.recvfrom(65535)
                parsed = Packet.from_dict(parse_packet(data))
                if parsed.dst_port != self.my_port:
                    continue

                if parsed.flags == FLAG_CLIENT_HELLO:
                    self.handle_client_hello(parsed)
                elif parsed.flags in (FLAG_DATA, FLAG_DATA_LAST):
                    self.handle_data(parsed)
                elif parsed.flags == FLAG_ACK:
                    self.handle_ack(parsed)
                elif parsed.flags == FLAG_REQ:
                    self.handle_req(parsed)
                elif parsed.flags == FLAG_FIN:
                    self.handle_fin(parsed)
            except OSError as e:
                print(f"[SERVER] Socket error: {e}")
                break
            except Exception as e:
                print(f"[SERVER] Error processing packet: {e}")
                import traceback
                traceback.print_exc()
                continue

    # ── handshake ─────────────────────────────────────────────────────

    def handle_client_hello(self, packet):
        """Verify ClientHello HMAC → send ServerHello → derive keys."""
        # If handshake already done, resend cached ServerHello
        if self.handshake_status == "Success" and self._cached_sh_raw:
            print("[SERVER] Duplicate ClientHello, resending cached ServerHello")
            try:
                self.sock.sendto(self._cached_sh_raw, self._cached_sh_addr)
                self.packets_sent += 1
            except OSError:
                pass
            return

        client_nonce = parse_client_hello(packet.payload, self.psk)
        if client_nonce is None:
            print("[SERVER] ClientHello HMAC verification FAILED — rejecting")
            self.handshake_status = "Fail"
            return

        print("[SERVER] ClientHello verified OK")

        # Build & send ServerHello
        sh_payload, server_nonce, session_id = build_server_hello(
            self.psk, client_nonce
        )
        sh_packet = Packet(
            version=4,
            ihl=5,
            total_length=20 + 8 + HEADER_SIZE + len(sh_payload),
            ttl=64,
            protocol=packet.protocol,
            src_ip=packet.dst_ip,
            dst_ip=packet.src_ip,
            src_port=packet.dst_port,
            dst_port=packet.src_port,
            udp_length=8 + HEADER_SIZE + len(sh_payload),
            udp_checksum=0,
            seq_num=0,
            ack_num=0,
            flags=FLAG_SERVER_HELLO,
            payload=sh_payload,
        )
        sh_raw = sh_packet.to_bytes()
        sh_addr = (sh_packet.dst_ip, sh_packet.dst_port)
        try:
            self.sock.sendto(sh_raw, sh_addr)
            self.packets_sent += 1
        except OSError as e:
            print(f"[SERVER] Failed to send ServerHello: {e}")
            return

        # Cache for duplicate ClientHello retransmissions
        self._cached_sh_raw = sh_raw
        self._cached_sh_addr = sh_addr

        # Derive session key (server direction = 0)
        enc_key = derive_session_key(self.psk, client_nonce, server_nonce)
        self.security_ctx = SecurityContext(enc_key, session_id, direction=0)
        self.handshake_status = "Success"
        print(f"[SERVER] Handshake SUCCESS  session_id={session_id.hex()}")

    # ── encrypted REQ handling ────────────────────────────────────────

    def handle_req(self, packet):
        """Decrypt REQ payload, then delegate to parent."""
        if not self.security_ctx:
            print("[SERVER] REQ before handshake — dropping")
            return
        plaintext = self.security_ctx.decrypt(
            packet.payload, packet.seq_num, packet.ack_num, packet.flags
        )
        if plaintext is None:
            print("[SERVER] AEAD failed for REQ — dropping")
            return
        packet.payload = plaintext
        super().handle_req(packet)

    # ── encrypted ACK handling ────────────────────────────────────────

    def handle_ack(self, packet):
        """Decrypt ACK payload, extract SHA-256 match byte if FIN ACK."""
        if self.security_ctx:
            plaintext = self.security_ctx.decrypt(
                packet.payload, packet.seq_num, packet.ack_num, packet.flags
            )
            if plaintext is None:
                print(f"[SERVER] AEAD failed for ACK ack={packet.ack_num}")
                return
            # FIN-ACK carries 1-byte SHA-256 match result from client
            if self.fin_sent and not self.fin_acked and len(plaintext) == 1:
                self.sha256_match = plaintext == b"\x01"
                print(
                    f"[SERVER] SHA-256 match from client: "
                    f"{'Yes' if self.sha256_match else 'No'}"
                )
            packet.payload = plaintext
        super().handle_ack(packet)

    # ── file transfer (encrypt chunks + SHA-256) ──────────────────────

    def transfer_file(self, file_path, req):
        """Read file, compute SHA-256, encrypt each chunk, queue packets."""
        print(f"[SERVER] secure transfer_file for {file_path}")
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            print(f"[SERVER] Read {len(data)} bytes")

            self.sha256_hash = compute_bytes_sha256(data)
            md5_hash = hashlib.md5(data).digest()

            chunk_size = MAX_PAYLOAD_SIZE - HEADER_SIZE - SECURITY_OVERHEAD
            chunks = []
            idx = 0
            offset = 0
            while offset < len(data):
                chunk = data[offset : offset + chunk_size]
                chunks.append((idx, chunk))
                offset += len(chunk)
                idx += 1

            with self.lock:
                self.pending_data_queue.clear()
                self.unacked_packets.clear()
                self.expiry_time.clear()
                self.left = 0
                self.right = 0

                self.file_size = len(data)
                self.md5_hash = md5_hash
                self.total_chunks = idx
                self.client_req = req
                self.all_chunks_queued = True
                self.start_time = time.monotonic()
                self.last_chunk_seq = idx - 1 if idx > 0 else -1

                for seq, chunk in chunks:
                    is_last = seq == self.last_chunk_seq
                    flags = FLAG_DATA_LAST if is_last else FLAG_DATA
                    encrypted = self.security_ctx.encrypt(
                        chunk, seq, 0, flags
                    )
                    pkt = Packet.get_data_packet(
                        encrypted, req, seq_num=seq, last=is_last
                    )
                    self.pending_data_queue.append(pkt)

                print(
                    f"[SERVER] Queued {idx} encrypted chunks, "
                    f"last_chunk_seq={self.last_chunk_seq}"
                )

                if idx == 0:
                    self._send_fin_packet()

        except Exception as e:
            print(f"[SERVER] transfer_file error: {e}")
            import traceback
            traceback.print_exc()
            with self.lock:
                self.reset_transfer_state()

    # ── encrypted FIN (carries SHA-256 digest) ────────────────────────

    def _send_fin_packet(self):
        """Encrypt SHA-256 hash and send FIN. Caller must hold lock."""
        if self.client_req is None:
            return
        print(f"[SERVER] Sending encrypted FIN  sha256={self.sha256_hash.hex()[:16]}…")
        encrypted_hash = self.security_ctx.encrypt(
            self.sha256_hash, 0, 0, FLAG_FIN
        )
        self.sent_fin_packet = Packet.get_fin_packet(self.client_req, encrypted_hash)
        try:
            self.sock.sendto(
                self.sent_fin_packet.to_bytes(),
                (self.sent_fin_packet.dst_ip, self.sent_fin_packet.dst_port),
            )
            self.fin_sent = True
            self.expiry_time["FIN"] = time.monotonic() + TIMEOUT
            self.fin_expiry = time.monotonic() + TIMEOUT
            self.packets_sent += 1
        except OSError as e:
            print(f"[SERVER] Error sending FIN: {e}")

    # ── Phase 2 output report ─────────────────────────────────────────

    def generate_output_report(self):
        """Write output.txt with Phase 1 + Phase 2 fields."""
        duration = self.end_time - self.start_time
        h = int(duration // 3600)
        m = int((duration % 3600) // 60)
        s = int(duration % 60)

        ctx = self.security_ctx
        aead_fail = ctx.aead_failures if ctx else 0
        replay_drop = ctx.replay_drops if ctx else 0
        sha_match = "Yes" if self.sha256_match else (
            "No" if self.sha256_match is False else "Pending"
        )

        with open("output.txt", "w") as f:
            f.write(f"Name of the transferred file: {self.requested_file_name}\n")
            f.write(f"Size of the transferred file: {self.file_size} bytes\n")
            f.write(
                f"The number of packets sent from the server: {self.packets_sent}\n"
            )
            f.write(
                f"The number of retransmitted packets from the server: "
                f"{self.retransmissions}\n"
            )
            f.write(
                f"The number of packets received from the client: "
                f"{self.packets_received}\n"
            )
            f.write(f"The time duration of the file transfer: {h:02d}:{m:02d}:{s:02d}\n")
            f.write(f"Security enabled (PSK + AEAD): Yes\n")
            f.write(f"Handshake status: {self.handshake_status}\n")
            f.write(
                f"AEAD authentication failures (invalid packets dropped): {aead_fail}\n"
            )
            f.write(
                f"Replay drops (duplicate/out-of-window packets): {replay_drop}\n"
            )
            f.write(f"SHA-256 match: {sha_match}\n")
        print("[SERVER] Output report written to output.txt")

    # ── state reset override ──────────────────────────────────────────

    def reset_transfer_state(self):
        """Reset per-transfer state; keep handshake / security context alive."""
        super().reset_transfer_state()
        self.sha256_hash = b""
        self.sha256_match = None


# ═══════════════════════════════════════════════════════════════════════════
#  SecureReceiver  (client)
# ═══════════════════════════════════════════════════════════════════════════

class SecureReceiver(Receiver):
    """
    Client-side secure receiver.

    Extends Receiver with:
      - ClientHello / ServerHello handshake (with retry)
      - AEAD decryption + replay check on incoming DATA / FIN
      - AEAD encryption of outgoing ACKs
      - SHA-256 end-to-end file verification
    """

    def __init__(self, sock, dest_ip, dest_port, psk):
        super().__init__(sock, dest_ip, dest_port)
        self.psk = psk
        self.security_ctx: Optional[SecurityContext] = None
        self.handshake_done = False
        self.handshake_status = "Pending"
        self._client_nonce = None  # kept for ServerHello verification
        self._sha256_match = None

    # ── receive loop override (adds SERVER_HELLO dispatch) ────────────

    def sliding_window_rcv(self):
        """Extended receive loop that also handles SERVER_HELLO."""
        print("[CLIENT] secure sliding_window_rcv thread started")
        while self.running:
            try:
                data, _ = self.sock.recvfrom(65535)
                parsed = Packet.from_dict(parse_packet(data))
                if parsed.dst_port != self.my_port:
                    continue

                if parsed.flags == FLAG_SERVER_HELLO:
                    self.handle_server_hello(parsed)
                elif parsed.flags in (FLAG_DATA, FLAG_DATA_LAST):
                    self.handle_data(parsed)
                elif parsed.flags == FLAG_ACK:
                    self.handle_ack(parsed)
                elif parsed.flags == FLAG_REQ:
                    self.handle_req(parsed)
                elif parsed.flags == FLAG_FIN:
                    self.handle_fin(parsed)
            except OSError as e:
                print(f"[CLIENT] Socket error: {e}")
                break
            except Exception as e:
                print(f"[CLIENT] Error processing packet: {e}")
                import traceback
                traceback.print_exc()
                continue

    # ── handshake ─────────────────────────────────────────────────────

    def handle_server_hello(self, packet):
        """Verify ServerHello HMAC, derive session key."""
        if self.handshake_done:
            return  # ignore duplicates

        server_nonce, session_id = parse_server_hello(
            packet.payload, self.psk, self._client_nonce
        )
        if server_nonce is None:
            print("[CLIENT] ServerHello HMAC verification FAILED")
            self.handshake_status = "Fail"
            return

        enc_key = derive_session_key(self.psk, self._client_nonce, server_nonce)
        self.security_ctx = SecurityContext(enc_key, session_id, direction=1)
        self.handshake_done = True
        self.handshake_status = "Success"
        print(f"[CLIENT] Handshake SUCCESS  session_id={session_id.hex()}")

    def _perform_handshake(self):
        """
        Send ClientHello with retransmission until ServerHello arrives.
        Returns True on success, False on failure/timeout.
        """
        ch_payload, self._client_nonce = build_client_hello(self.psk)

        ch_packet = Packet(
            version=4,
            ihl=5,
            total_length=20 + 8 + HEADER_SIZE + len(ch_payload),
            ttl=64,
            protocol=socket.IPPROTO_UDP,
            src_ip=CLIENT_IP,
            dst_ip=self.dest_ip,
            src_port=CLIENT_PORT,
            dst_port=self.dest_port,
            udp_length=8 + HEADER_SIZE + len(ch_payload),
            udp_checksum=0,
            seq_num=0,
            ack_num=0,
            flags=FLAG_CLIENT_HELLO,
            payload=ch_payload,
        )
        ch_raw = ch_packet.to_bytes()
        ch_addr = (self.dest_ip, self.dest_port)

        for attempt in range(1, HANDSHAKE_MAX_RETRIES + 1):
            print(f"[CLIENT] Sending ClientHello (attempt {attempt})")
            try:
                self.sock.sendto(ch_raw, ch_addr)
                self.packets_sent += 1
            except OSError as e:
                print(f"[CLIENT] Failed to send ClientHello: {e}")
                return False

            deadline = time.monotonic() + HANDSHAKE_TIMEOUT
            while time.monotonic() < deadline:
                if self.handshake_done:
                    return True
                if self.handshake_status == "Fail":
                    return False
                time.sleep(0.05)

        print("[CLIENT] Handshake timed out after max retries")
        self.handshake_status = "Fail"
        return False

    # ── encrypted DATA handling ───────────────────────────────────────

    def handle_data(self, packet):
        """Decrypt DATA payload, check replay, store, send encrypted ACK.

        On replay (retransmission from server due to lost ACK), we still
        re-send the cumulative ACK so the sender can advance its window.
        Only AEAD failures are silently dropped.
        """
        with self.lock:
            if not self.security_ctx:
                print("[CLIENT] DATA before handshake — dropping")
                return

            # Decrypt — AEAD failure means tampered/forged → drop silently
            plaintext = self.security_ctx.decrypt(
                packet.payload, packet.seq_num, packet.ack_num, packet.flags
            )
            if plaintext is None:
                print(f"[CLIENT] AEAD failed for DATA seq={packet.seq_num}")
                return

            # Replay check — retransmission is a "replay" but we must ACK it
            is_replay = self.security_ctx.check_replay(packet.seq_num, packet.flags)

            if is_replay:
                print(f"[CLIENT] Retransmit/replay DATA seq={packet.seq_num}, re-ACKing")
            else:
                is_last = packet.flags == FLAG_DATA_LAST
                suffix = " (LAST)" if is_last else ""
                print(f"[CLIENT] Decrypted DATA seq={packet.seq_num}{suffix}")
                self.received_data[packet.seq_num] = plaintext
                self.data_received = True
                self.packets_received += 1
                if self.start_time == 0.0:
                    self.start_time = time.monotonic()

            # Always send cumulative ACK (even for replays / retransmissions)
            ack_num = 0
            while ack_num in self.received_data:
                ack_num += 1

            encrypted_empty = self.security_ctx.encrypt(b"", 0, ack_num, FLAG_ACK)
            ack_pkt = Packet.get_ack_packet(packet, ack_num)
            ack_pkt.payload = encrypted_empty
            print(f"[CLIENT] Sending encrypted ACK {ack_num}")
            try:
                self.sock.sendto(
                    ack_pkt.to_bytes(), (ack_pkt.dst_ip, ack_pkt.dst_port)
                )
                self.packets_sent += 1
            except OSError:
                pass

    # ── encrypted FIN handling ────────────────────────────────────────

    def handle_fin(self, packet):
        """
        Decrypt FIN → extract SHA-256 → assemble file → verify digest →
        send encrypted ACK with match result → cleanup.
        """
        with self.lock:
            if not self.requested_file:
                print("[CLIENT] Ignoring FIN (no active request)")
                return
            if not self.security_ctx:
                print("[CLIENT] FIN before handshake — dropping")
                return

            # Decrypt SHA-256 digest
            plaintext = self.security_ctx.decrypt(
                packet.payload, packet.seq_num, packet.ack_num, packet.flags
            )
            if plaintext is None:
                print("[CLIENT] AEAD failed for FIN")
                return

            # Replay check for FIN
            if self.security_ctx.check_replay(packet.seq_num, packet.flags):
                print("[CLIENT] Replay detected for FIN")
                return

            server_sha256 = plaintext
            print(f"[CLIENT] Received FIN  sha256={server_sha256.hex()[:16]}…")

            self.transfer_complete = True
            self.data_received = True
            self.req_retransmit_active = False

            # Compute cumulative ACK BEFORE assembling (which clears received_data)
            ack_num = 0
            while ack_num in self.received_data:
                ack_num += 1

            # Assemble file
            self._assemble_file_internal()

            # Verify SHA-256
            output_path = self.output_file if self.output_file else self.requested_file
            try:
                local_sha256 = compute_file_sha256(output_path)
                self._sha256_match = local_sha256 == server_sha256
                if self._sha256_match:
                    print("[CLIENT] SHA-256 verification PASSED")
                else:
                    print("[CLIENT] SHA-256 verification FAILED")
                    print(f"  Server: {server_sha256.hex()}")
                    print(f"  Local:  {local_sha256.hex()}")
            except FileNotFoundError:
                print(f"[CLIENT] Output file not found for SHA-256 check")
                self._sha256_match = False

            # Send encrypted ACK with match result byte
            match_byte = b"\x01" if self._sha256_match else b"\x00"
            encrypted_match = self.security_ctx.encrypt(
                match_byte, 0, ack_num, FLAG_ACK
            )
            ack_pkt = Packet.get_ack_packet(packet, ack_num)
            ack_pkt.payload = encrypted_match
            print(f"[CLIENT] Sending FIN-ACK {ack_num} (sha256_match={self._sha256_match})")
            try:
                self.sock.sendto(
                    ack_pkt.to_bytes(), (ack_pkt.dst_ip, ack_pkt.dst_port)
                )
                self.packets_sent += 1
            except OSError as e:
                print(f"[CLIENT] Error sending FIN-ACK: {e}")

            self.end_time = time.monotonic()
            self._print_client_report()
            self.cleanup()
            self._reset_receiver_state_no_lock()
            # Mark complete AFTER reset so the main loop in SRFT_UDPClient
            # sees it and exits cleanly
            self.transfer_complete = True

    def _assemble_file_internal(self):
        """Write received decrypted data to file in order. Caller holds lock."""
        if not self.requested_file:
            return
        file_bytes = b""
        seq = 0
        while seq in self.received_data:
            file_bytes += self.received_data.pop(seq)
            seq += 1
        output_path = self.output_file if self.output_file else self.requested_file
        with open(output_path, "wb") as f:
            f.write(file_bytes)
        print(f"[CLIENT] Assembled {len(file_bytes)} bytes → {output_path}")

    def _print_client_report(self):
        """Print client-side transfer summary."""
        if self.start_time == 0.0 or self.end_time == 0.0:
            return
        duration = self.end_time - self.start_time
        print(f"[CLIENT] Transfer complete in {duration:.2f}s")
        print(f"  Packets received: {self.packets_received}")
        print(f"  Packets sent (ACKs): {self.packets_sent}")
        print(f"  SHA-256 match: {'Yes' if self._sha256_match else 'No'}")
        ctx = self.security_ctx
        if ctx:
            print(f"  AEAD failures: {ctx.aead_failures}")
            print(f"  Replay drops: {ctx.replay_drops}")

    # ── main entry point ──────────────────────────────────────────────

    def request_file(self, filename, output_path=None):
        """
        Client entry point:
        1. Start receive thread
        2. Perform handshake (with retry)
        3. Send encrypted REQ
        4. Wait for encrypted DATA → ACK loop
        """
        # Stop any previous transfer
        self.req_retransmit_active = False
        self.transfer_complete = True
        time.sleep(0.2)

        with self.lock:
            self._reset_receiver_state_no_lock()

        # Reset handshake state for fresh connection
        self.handshake_done = False
        self.handshake_status = "Pending"
        self.security_ctx = None
        self._client_nonce = None
        self._sha256_match = None
        self.running = True
        self.transfer_complete = False

        # Start receive thread (handles ServerHello + DATA + FIN)
        if not self.receiver_thread_started or not self.running:
            rcv_thread = threading.Thread(target=self.sliding_window_rcv)
            rcv_thread.daemon = True
            rcv_thread.start()
            self.receiver_thread_started = True

        # ── Phase 2 handshake ──
        if not self._perform_handshake():
            print("[CLIENT] Handshake FAILED — aborting file request")
            return

        # ── Send encrypted REQ ──
        req_payload = filename.encode()
        encrypted_req = self.security_ctx.encrypt(
            req_payload, 0, 0, FLAG_REQ
        )
        req_packet = Packet(
            version=4,
            ihl=5,
            total_length=20 + 8 + HEADER_SIZE + len(encrypted_req),
            ttl=64,
            protocol=socket.IPPROTO_UDP,
            src_ip=CLIENT_IP,
            dst_ip=self.dest_ip,
            src_port=CLIENT_PORT,
            dst_port=self.dest_port,
            udp_length=8 + HEADER_SIZE + len(encrypted_req),
            udp_checksum=0,
            seq_num=0,
            ack_num=0,
            flags=FLAG_REQ,
            payload=encrypted_req,
        )

        self.req_packet = req_packet
        self.req_attempts = 1
        self.req_expiry = time.monotonic() + TIMEOUT
        self.start_time = time.monotonic()
        self.data_received = False
        self.req_retransmit_active = True
        self.transfer_complete = False

        print(f"[CLIENT] Sending encrypted REQ for {filename}")
        try:
            self.sock.sendto(req_packet.to_bytes(), (self.dest_ip, self.dest_port))
            self.packets_sent += 1
        except OSError as e:
            print(f"[CLIENT] Error sending REQ: {e}")
            return

        self.requested_file = filename
        self.output_file = output_path if output_path else filename

        # Start REQ retransmission thread
        retransmit_thread = threading.Thread(target=self._req_retransmit_loop)
        retransmit_thread.daemon = True
        retransmit_thread.start()