import threading
import hashlib
from typing import Optional
import time
from config import *
from packet import *
from app_packet import Packet, HEADER_SIZE
from transfer_base import ReliableTransferBase


class Sender(ReliableTransferBase):
    """
    Server-side reliable transfer: sends file chunks, processes ACKs.
    """

    def __init__(self, sock, dest_ip, dest_port):
        super().__init__(
            sock, dest_ip, dest_port, my_port=SERVER_PORT, bind_ip=SERVER_IP
        )

        self.pending_data_queue = []
        self.unacked_packets = []
        self.client_req = None  # The REQ packet that initiated transfer
        self.all_chunks_queued = False
        self.fin_sent = False
        self.fin_acked = False
        self.fin_expiry = 0.0
        self.md5_hash = b""
        self.total_chunks = 0
        self.requested_file_name = ""

    def sliding_window_send(self):
        """
        Sender thread: sends packets from pending queue, retransmits on timeout.
        """
        while self.running:
            with self.lock:
                # Send if window not full and we have pending data
                if self.pending_data_queue and self.right - self.left < WINDOW_SIZE:
                    packet = self.pending_data_queue.pop(0)
                    try:
                        raw = packet.to_bytes()
                        self.sock.sendto(raw, (packet.dst_ip, packet.dst_port))
                        self.unacked_packets.append(packet)
                        self.expiry_time[packet.seq_num] = time.monotonic() + TIMEOUT
                        if packet.seq_num >= self.right:
                            self.right = packet.seq_num + 1
                        self.packets_sent += 1
                    except (OSError, AttributeError):
                        # Socket might be closed
                        self.running = False

            # Retransmit FIN if not acknowledged
            with self.lock:
                now = time.monotonic()
                if (
                    self.client_req is not None
                    and self.fin_sent
                    and not self.fin_acked
                    and now > self.fin_expiry
                ):
                    print(f"[SERVER] Retransmitting FIN for {self.requested_file_name}")
                    try:
                        fin_packet = Packet.get_fin_packet(
                            self.client_req, self.md5_hash
                        )
                        self.sock.sendto(
                            fin_packet.to_bytes(),
                            (fin_packet.dst_ip, fin_packet.dst_port),
                        )
                        self.fin_expiry = now + TIMEOUT
                        self.packets_sent += 1
                        self.retransmissions += 1
                    except (OSError, AttributeError):
                        # Socket might be closed
                        self.running = False

    def handle_ack(self, packet):
        """
        Process ACK: update window, cleanup acknowledged packets,
        send FIN if all chunks transferred and acknowledged.
        """
        with self.lock:
            self.left = packet.ack_num
            self.packets_received += 1

            # Remove packets that have been acknowledged
            to_remove = [p for p in self.unacked_packets if p.seq_num < packet.ack_num]
            for p in to_remove:
                self.expiry_time.pop(p.seq_num, None)
            self.unacked_packets = [
                p for p in self.unacked_packets if p.seq_num >= packet.ack_num
            ]

            # Send FIN if all done
            if (
                self.all_chunks_queued
                and not self.pending_data_queue
                and not self.unacked_packets
                and not self.fin_sent
                and self.client_req is not None
            ):
                try:
                    fin_packet = Packet.get_fin_packet(self.client_req, self.md5_hash)
                    self.sock.sendto(
                        fin_packet.to_bytes(), (fin_packet.dst_ip, fin_packet.dst_port)
                    )
                    self.fin_sent = True
                    self.fin_expiry = time.monotonic() + TIMEOUT
                    self.packets_sent += 1
                except (OSError, AttributeError):
                    # Socket might be closed
                    pass

            # Check if this ACK acknowledges FIN (ACK number equals total chunks after FIN sent)
            if (
                self.fin_sent
                and not self.fin_acked
                and packet.ack_num == self.total_chunks
            ):
                self.fin_acked = True
                self.end_time = time.monotonic()
                self.generate_output_report()
                self.reset_transfer_state()

    def generate_output_report(self):
        """Generate output.txt with transfer statistics."""
        duration = self.end_time - self.start_time
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        with open("output.txt", "w") as f:
            f.write(f"Name of the transferred file: {self.requested_file_name}\n")
            f.write(f"Size of the transferred file: {self.file_size} bytes\n")
            f.write(
                f"The number of packets sent from the server: {self.packets_sent}\n"
            )
            f.write(
                f"The number of retransmitted packets from the server: {self.retransmissions}\n"
            )
            f.write(
                f"The number of packets received from the client: {self.packets_received}\n"
            )
            f.write(f"The time duration of the file transfer: {time_str}\n")
        print(f"[INFO] Output report written to output.txt")

    def reset_transfer_state(self):
        """Reset sender state for next transfer. Caller must hold lock."""
        print(f"[SERVER] reset_transfer_state called")
        self.pending_data_queue.clear()
        self.unacked_packets.clear()
        self.expiry_time.clear()
        self.client_req = None
        self.all_chunks_queued = False
        self.fin_sent = False
        self.fin_acked = False
        self.fin_expiry = 0.0
        self.md5_hash = b""
        self.total_chunks = 0
        self.left = 0
        self.right = 0
        # Keep metrics for report already saved, but reset for next transfer
        self.start_time = 0.0
        self.end_time = 0.0
        self.packets_sent = 0
        self.retransmissions = 0
        self.packets_received = 0
        self.file_size = 0

    def handle_req(self, packet):
        """
        Received file request: start file transfer.
        """
        requested_file = packet.payload.decode()
        print(f"[SERVER] Received REQ for {requested_file}")

        with self.lock:
            # Check if we're already processing a transfer
            if self.client_req is not None:
                print(
                    f"[SERVER] Already processing transfer for {self.requested_file_name}, ignoring duplicate REQ"
                )
                return

            self.reset_transfer_state()
            self.requested_file_name = requested_file
            print(f"[SERVER] Calling transfer_file for {requested_file}")
            self.transfer_file(requested_file, packet)

        print(f"[SERVER] REQ handled for {requested_file}")

    def transfer_file(self, file_path: str, req: Packet) -> None:
        """
        Read file, split into chunks, add DATA packets to pending queue.
        """
        print(f"[SERVER] transfer_file called for {file_path}")
        # Clear any previous pending data
        self.pending_data_queue.clear()
        self.unacked_packets.clear()
        self.expiry_time.clear()
        self.left = 0
        self.right = 0

        try:
            with open(file_path, "rb") as f:
                data = f.read()
                print(f"[SERVER] Read {len(data)} bytes from {file_path}")
                self.file_size = len(data)
                self.md5_hash = hashlib.md5(data).digest()  # 16 bytes
                CHUNK_SIZE = MAX_PAYLOAD_SIZE - HEADER_SIZE
                i = 0
                chunk_idx = 0
                while i < len(data):
                    chunk = data[i : i + CHUNK_SIZE]
                    self.pending_data_queue.append(
                        Packet.get_data_packet(chunk, req, seq_num=chunk_idx)
                    )
                    i += len(chunk)
                    chunk_idx += 1
                self.total_chunks = chunk_idx
                self.client_req = req
                self.all_chunks_queued = True
                self.start_time = time.monotonic()
                print(
                    f"[SERVER] Created {chunk_idx} chunks, pending queue size: {len(self.pending_data_queue)}"
                )

        except Exception as e:
            print(f"Encountered {e} while trying to read file {file_path}")

    def listen_and_serve(self) -> None:
        """
        Server entry point: start sender and receiver threads.
        """
        send_thread = threading.Thread(target=self.sliding_window_send)
        rcv_thread = threading.Thread(target=self.sliding_window_rcv)
        send_thread.daemon = True
        rcv_thread.daemon = True

        send_thread.start()
        rcv_thread.start()

    def request_file(self, filename: str, output_path: Optional[str] = None):
        """Sender does not request files"""
        raise NotImplementedError("Sender cannot request files")


class Receiver(ReliableTransferBase):
    """
    Client-side reliable transfer: requests file, receives DATA, sends ACKs.
    """

    def __init__(self, sock, dest_ip, dest_port):
        super().__init__(
            sock, dest_ip, dest_port, my_port=CLIENT_PORT, bind_ip=CLIENT_IP
        )

        self.received_data = {}
        self.requested_file = ""
        self.output_file = ""
        self.req_attempts = 0
        self.req_expiry = 0.0
        self.req_max_attempts = 3
        self.server_md5 = b""
        self.transfer_complete = False
        self.start_time = 0.0
        self.req_packet = None
        self.data_received = False
        self.req_retransmit_active = True
        self.receiver_thread_started = False

    def handle_data(self, packet):
        """
        Store DATA payload, send cumulative ACK.
        """
        with self.lock:
            self.received_data[packet.seq_num] = packet.payload
            self.data_received = True  # Signal that we got data
            self.packets_received += 1
            if self.start_time == 0.0:
                self.start_time = time.monotonic()

            # cumulative ACK
            ack_num = 0
            while ack_num in self.received_data:
                ack_num += 1

            # Send ACK
            try:
                ack_packet = Packet.get_ack_packet(packet, ack_num)
                raw = ack_packet.to_bytes()
                self.sock.sendto(raw, (ack_packet.dst_ip, ack_packet.dst_port))
                self.packets_sent += 1
            except (OSError, AttributeError):
                # Socket might be closed
                pass

    def handle_fin(self, packet):
        """
        Received FIN: extract MD5, send ACK, assemble file, verify MD5, cleanup.
        """
        with self.lock:
            self.server_md5 = packet.payload  # MD5 hash from server
            print(f"[CLIENT] Received FIN for {self.requested_file}")
            # Send ACK for FIN (cumulative ACK for all data)
            ack_num = 0
            while ack_num in self.received_data:
                ack_num += 1
            try:
                ack_packet = Packet.get_ack_packet(packet, ack_num)
                raw = ack_packet.to_bytes()
                self.sock.sendto(raw, (ack_packet.dst_ip, ack_packet.dst_port))
                self.packets_sent += 1  # ACK is sent packet
            except (OSError, AttributeError):
                # Socket might be closed
                pass

            # Mark transfer complete to stop retransmission
            self.transfer_complete = True
            self.data_received = True  # For empty files
            self.req_retransmit_active = False

            # Assemble file and verify MD5
            self.assemble_file()
            self.verify_md5()
            self.end_time = time.monotonic()
            self.generate_client_report()
            self.cleanup()
            self._reset_receiver_state_no_lock()

    def assemble_file(self) -> None:
        """
        Write received data to file in sequence order.
        """
        if not self.requested_file:
            print("No file requested, cannot assemble")
            return

        file_bytes = b""
        seq = 0
        while seq in self.received_data:
            file_bytes += self.received_data.pop(seq)
            seq += 1

        output_path = self.output_file if self.output_file else self.requested_file
        with open(output_path, "wb") as f:
            f.write(file_bytes)

    def verify_md5(self):
        """Compute MD5 of received file and compare with server's hash."""
        if not self.requested_file:
            return
        output_path = self.output_file if self.output_file else self.requested_file
        try:
            with open(output_path, "rb") as f:
                received_hash = hashlib.md5(f.read()).digest()
            if received_hash == self.server_md5:
                print(f"[SUCCESS] MD5 verification passed")
            else:
                print(f"[FAILURE] MD5 verification failed")
                print(f"  Server MD5: {self.server_md5.hex()}")
                print(f"  Client MD5: {received_hash.hex()}")
        except FileNotFoundError:
            print(f"[ERROR] Output file not found: {output_path}")

    def generate_client_report(self):
        """Print client-side transfer statistics."""
        if self.start_time == 0.0 or self.end_time == 0.0:
            return
        duration = self.end_time - self.start_time
        print(f"[CLIENT] Transfer completed in {duration:.2f} seconds")
        print(f"  Packets received: {self.packets_received}")
        print(f"  Packets sent (ACKs): {self.packets_sent}")
        print(f"  File: {self.requested_file} -> {self.output_file}")

    def _reset_receiver_state_no_lock(self):
        """Reset receiver state without acquiring lock (caller must hold lock)."""
        self.received_data.clear()
        self.requested_file = ""
        self.output_file = ""
        self.req_attempts = 0
        self.req_expiry = 0.0
        self.server_md5 = b""
        self.transfer_complete = False  # Reset for next transfer
        self.data_received = False
        self.start_time = 0.0
        self.end_time = 0.0
        self.packets_received = 0
        self.packets_sent = 0
        self.req_packet = None
        self.req_retransmit_active = False

    def reset_receiver_state(self):
        """Reset receiver state for next transfer."""
        with self.lock:
            self._reset_receiver_state_no_lock()

    def _req_retransmit_loop(self):
        """Retransmit REQ packet until DATA received or transfer complete or max attempts exceeded."""
        while (
            self.req_attempts < self.req_max_attempts
            and not self.data_received
            and not self.transfer_complete
            and self.req_retransmit_active
        ):
            now = time.monotonic()
            if now > self.req_expiry:
                with self.lock:
                    if (
                        self.req_packet is not None
                        and not self.data_received
                        and not self.transfer_complete
                        and self.req_retransmit_active
                    ):
                        try:
                            self.sock.sendto(
                                self.req_packet.to_bytes(),
                                (self.dest_ip, self.dest_port),
                            )
                            self.req_attempts += 1
                            self.packets_sent += 1
                            self.req_expiry = now + TIMEOUT
                            print(
                                f"[CLIENT] REQ retransmission attempt {self.req_attempts}"
                            )
                        except (OSError, AttributeError):
                            # Socket might be closed
                            self.req_retransmit_active = False
                            break
                if self.req_attempts >= self.req_max_attempts:
                    print("[CLIENT] Max REQ attempts exceeded, aborting transfer")
                    self.req_retransmit_active = False
                    self.running = False  # Stop receiver thread
                    break
            time.sleep(0.1)
        # Clean up retransmission state
        self.req_retransmit_active = False

    def request_file(self, filename: str, output_path: Optional[str] = None) -> None:
        """
        Client entry point: send REQ packet, start retransmission and receiver threads.
        """
        # Stop any existing retransmission thread
        self.req_retransmit_active = False
        self.transfer_complete = True  # Signal any existing loop to exit
        time.sleep(0.2)  # Allow existing thread to exit

        # Reset state for new transfer
        with self.lock:
            self._reset_receiver_state_no_lock()

        # Ensure receiver thread will run
        self.running = True

        req_packet = Packet.get_req_packet(
            filename=filename,
            src_ip=CLIENT_IP,
            dst_ip=self.dest_ip,
            src_port=CLIENT_PORT,
            dst_port=self.dest_port,
        )
        self.req_packet = req_packet
        self.req_attempts = 1
        self.req_expiry = time.monotonic() + TIMEOUT
        self.start_time = time.monotonic()
        self.data_received = False
        self.req_retransmit_active = True
        self.transfer_complete = False

        print(f"[CLIENT] Sending REQ for {filename}")
        try:
            self.sock.sendto(req_packet.to_bytes(), (self.dest_ip, self.dest_port))
            self.packets_sent += 1
        except (OSError, AttributeError) as e:
            print(f"[CLIENT] Error sending REQ: {e}")
            return

        self.requested_file = filename
        self.output_file = output_path if output_path else filename

        # Start retransmission thread
        retransmit_thread = threading.Thread(target=self._req_retransmit_loop)
        retransmit_thread.daemon = True
        retransmit_thread.start()

        # Start receiver thread if not already running
        if not self.receiver_thread_started or not self.running:
            rcv_thread = threading.Thread(target=self.sliding_window_rcv)
            rcv_thread.daemon = True
            rcv_thread.start()
            self.receiver_thread_started = True
            self.running = True

    def listen_and_serve(self):
        """Receiver does not listen and serve"""
        raise NotImplementedError("Receiver cannot listen and serve")
