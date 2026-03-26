import threading
import hashlib
import time
from collections import defaultdict
from typing import Optional
from config import *
from packet import *
from app_packet import Packet, HEADER_SIZE


class ReliableTransferBase:
    """
    Shared infrastructure for both sender and receiver.
    Not meant to be instantiated directly.
    """

    def __init__(self, sock, dest_ip, dest_port, my_port):
        self.sock = sock
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.my_port = my_port

        # Sliding window state
        self.left, self.right = 0, 0
        self.lock = threading.Lock()

        # Buffers (specific to sender/receiver will be initialized in subclasses)
        self.expiry_time = defaultdict(float)

    def sliding_window_rcv(self):
        """
        Main receive loop - dispatches to handler methods based on packet type.
        """
        while True:
            data, _ = self.sock.recvfrom(65535)
            parsed = Packet.from_dict(parse_packet(data))
            if parsed.dst_port != self.my_port:
                continue

            if parsed.flags == FLAG_DATA:
                self.handle_data(parsed)
            elif parsed.flags == FLAG_ACK:
                self.handle_ack(parsed)
            elif parsed.flags == FLAG_REQ:
                self.handle_req(parsed)
            elif parsed.flags == FLAG_FIN:
                self.handle_fin(parsed)

    def handle_data(self, packet):
        """Handle DATA packet - override in receiver"""
        pass

    def handle_ack(self, packet):
        """Handle ACK packet - override in sender"""
        pass

    def handle_req(self, packet):
        """Handle REQ packet - override in sender"""
        pass

    def handle_fin(self, packet):
        """Handle FIN packet - override in receiver"""
        pass

    def md5(self, filepath):
        """Compute MD5 hash of a file"""
        with open(filepath, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()

    def cleanup(self):
        # TODO: Close sockets used and any other cleanup
        # TODO: Write the output stub
        ...


class Sender(ReliableTransferBase):
    """
    Server-side reliable transfer: sends file chunks, processes ACKs.
    """

    def __init__(self, sock, dest_ip, dest_port):
        super().__init__(sock, dest_ip, dest_port, my_port=SERVER_PORT)

        # Bind socket to server IP
        try:
            self.sock.bind((SERVER_IP, 0))  # port 0 for raw socket
        except OSError:
            # Socket may already be bound, ignore
            pass

        # Sender-specific buffers with descriptive names
        self.pending_data_queue = []  # DATA packets waiting to be sent
        self.unacked_packets = []  # Packets sent but not yet acknowledged
        self.client_req = None  # The REQ packet that initiated transfer
        self.all_chunks_queued = False  # All file chunks added to pending queue
        self.fin_sent = False  # FIN packet sent flag

    def sliding_window_send(self):
        """
        Sender thread: sends packets from pending queue, retransmits on timeout.
        """
        while True:
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
                    except:
                        self.pending_data_queue.insert(0, packet)

            # Check for timeouts and retransmit
            with self.lock:
                now = time.monotonic()
                for packet in self.unacked_packets:
                    exp = self.expiry_time.get(packet.seq_num)
                    if exp and now > exp:
                        raw = packet.to_bytes()
                        self.sock.sendto(raw, (packet.dst_ip, packet.dst_port))
                        self.expiry_time[packet.seq_num] = now + TIMEOUT

    def handle_data(self, packet):
        """Sender ignores DATA packets"""
        pass

    def handle_ack(self, packet):
        """
        Process ACK: update window, cleanup acknowledged packets,
        send FIN if all chunks transferred and acknowledged.
        """
        with self.lock:
            self.left = packet.ack_num

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
                fin_packet = Packet.get_fin_packet(self.client_req)
                self.sock.sendto(
                    fin_packet.to_bytes(), (fin_packet.dst_ip, fin_packet.dst_port)
                )
                self.fin_sent = True

    def handle_req(self, packet):
        """
        Received file request: start file transfer.
        """
        requested_file = str(packet.payload)
        self.transfer_file(requested_file, packet)

    def handle_fin(self, packet):
        """Sender ignores FIN packets"""
        pass

    def transfer_file(self, file_path: str, req: Packet) -> None:
        """
        Read file, split into chunks, add DATA packets to pending queue.
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read()
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
                self.client_req = req
                self.all_chunks_queued = True

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
        super().__init__(sock, dest_ip, dest_port, my_port=CLIENT_PORT)

        # Bind socket to client IP (raw socket binding to IP only, port irrelevant)
        try:
            self.sock.bind((CLIENT_IP, 0))  # port 0 for raw socket
        except OSError:
            # Socket may already be bound, ignore
            pass

        # Receiver-specific buffers
        self.received_data = {}  # seq_num -> payload
        self.requested_file = ""  # Name of requested file
        self.output_file = ""  # Where to save received file

    def handle_data(self, packet):
        """
        Store DATA payload, send cumulative ACK.
        """
        with self.lock:
            self.received_data[packet.seq_num] = packet.payload

            # Calculate cumulative ACK (first missing sequence number)
            ack_num = 0
            while ack_num in self.received_data:
                ack_num += 1

            # Send ACK
            ack_packet = Packet.get_ack_packet(packet, ack_num)
            raw = ack_packet.to_bytes()
            self.sock.sendto(raw, (ack_packet.dst_ip, ack_packet.dst_port))

    def handle_ack(self, packet):
        """Receiver ignores ACK packets"""
        pass

    def handle_req(self, packet):
        """Receiver ignores REQ packets"""
        pass

    def handle_fin(self, packet):
        """
        Received FIN: assemble file, compute MD5, cleanup.
        """
        self.assemble_file()
        self.cleanup()

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

    def listen_and_serve(self):
        """Receiver does not listen and serve"""
        raise NotImplementedError("Receiver cannot listen and serve")

    def request_file(self, filename: str, output_path: Optional[str] = None) -> None:
        """
        Client entry point: send REQ packet, start receiver thread.
        """
        # Create REQ packet using factory method
        req_packet = Packet.get_req_packet(
            filename=filename,
            src_ip=CLIENT_IP,
            dst_ip=self.dest_ip,
            src_port=CLIENT_PORT,
            dst_port=self.dest_port,
        )

        self.sock.sendto(req_packet.to_bytes(), (self.dest_ip, self.dest_port))

        self.requested_file = filename
        self.output_file = output_path if output_path else filename

        # Start receiver thread
        rcv_thread = threading.Thread(target=self.sliding_window_rcv)
        rcv_thread.daemon = True
        rcv_thread.start()


class ReliableTransfer:
    """
    # Server side — waits for a request, then sends
    rt = ReliableTransfer(sock, role='sender')
    rt.listen_and_serve()  # listens for REQ, then sends the file

    # Client side — requests a file, then receives
    rt = ReliableTransfer(sock, dest_ip, dest_port, role='receiver')
    rt.request_file('photo.jpg', 'output.jpg')
    """

    def __init__(self, sock, dest_ip, dest_port, role):
        if role == "sender":
            self.impl = Sender(sock, dest_ip, dest_port)
        else:  # "receiver"
            self.impl = Receiver(sock, dest_ip, dest_port)
        self.role = role

    # Delegate methods to implementation
    def listen_and_serve(self):
        if self.role != "sender":
            raise ValueError("listen_and_serve() only for sender role")
        return self.impl.listen_and_serve()

    def request_file(self, filename: str, output_path: Optional[str] = None):
        if self.role != "receiver":
            raise ValueError("request_file() only for receiver role")
        return self.impl.request_file(filename, output_path)

    def md5(self, filepath):
        return self.impl.md5(filepath)

    def cleanup(self):
        return self.impl.cleanup()
