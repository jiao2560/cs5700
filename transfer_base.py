import threading
import hashlib
import time
from collections import defaultdict
from config import *
from packet import *
from app_packet import Packet


class ReliableTransferBase:
    """
    Shared infrastructure for both sender and receiver.
    Not meant to be instantiated directly.
    """

    def __init__(self, sock, dest_ip, dest_port, my_port, bind_ip=None):
        self.sock = sock
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.my_port = my_port

        # Bind socket if IP provided (raw socket binding to IP only)
        if bind_ip:
            try:
                self.sock.bind((bind_ip, 0))  # port 0 for raw socket
            except OSError:
                # Socket may already be bound, ignore
                pass

        # Sliding window state
        self.left, self.right = 0, 0
        self.lock = threading.Lock()

        # Buffers (specific to sender/receiver will be initialized in subclasses)
        self.expiry_time = defaultdict(float)

        # Metrics tracking
        self.start_time = 0.0
        self.end_time = 0.0
        self.packets_sent = 0
        self.retransmissions = 0
        self.packets_received = 0
        self.file_size = 0
        self.running = True

    def sliding_window_rcv(self):
        """
        Main receive loop - dispatches to handler methods based on packet type.
        """
        print(f"[{self.__class__.__name__}] sliding_window_rcv thread started")
        while self.running:
            try:
                data, _ = self.sock.recvfrom(65535)
                parsed = Packet.from_dict(parse_packet(data))
                if parsed.dst_port != self.my_port:
                    continue

                if parsed.flags in (FLAG_DATA, FLAG_DATA_LAST):
                    self.handle_data(parsed)
                elif parsed.flags == FLAG_ACK:
                    self.handle_ack(parsed)
                elif parsed.flags == FLAG_REQ:
                    self.handle_req(parsed)
                elif parsed.flags == FLAG_FIN:
                    self.handle_fin(parsed)
            except OSError as e:
                # Socket closed or unrecoverable error, break loop
                print(
                    f"[{self.__class__.__name__}] Socket error, receive thread exiting: {e}"
                )
                break
            except Exception as e:
                # Parsing or other non-fatal error, log and continue
                print(f"[{self.__class__.__name__}] Error processing packet: {e}")
                import traceback

                traceback.print_exc()
                continue

    def handle_data(self, packet):
        """Handle DATA packet - override in receiver"""
        print(
            f"[WARN] {self.__class__.__name__} ignoring DATA packet (flags={packet.flags})"
        )

    def handle_ack(self, packet):
        """Handle ACK packet - override in sender"""
        print(
            f"[WARN] {self.__class__.__name__} ignoring ACK packet (flags={packet.flags})"
        )

    def handle_req(self, packet):
        """Handle REQ packet - override in sender"""
        print(
            f"[WARN] {self.__class__.__name__} ignoring REQ packet (flags={packet.flags})"
        )

    def handle_fin(self, packet):
        """Handle FIN packet - override in receiver"""
        print(
            f"[WARN] {self.__class__.__name__} ignoring FIN packet (flags={packet.flags})"
        )

    def md5(self, filepath):
        """Compute MD5 hash of a file"""
        with open(filepath, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()

    def cleanup(self):
        # TODO: Close sockets used and any other cleanup
        # TODO: Write the output stub
        print(f"[INFO] {self.__class__.__name__} cleanup called")

    def reset_state(self):
        """Reset transfer state for next file transfer."""
        with self.lock:
            self.left, self.right = 0, 0
            self.expiry_time.clear()
            self.start_time = 0.0
            self.end_time = 0.0
            self.packets_sent = 0
            self.retransmissions = 0
            self.packets_received = 0
            self.file_size = 0
            self.running = True
