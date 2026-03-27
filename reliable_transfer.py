import threading
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
        super().__init__(
            sock, dest_ip, dest_port, my_port=CLIENT_PORT, bind_ip=CLIENT_IP
        )

        self.received_data = {}
        self.requested_file = ""
        self.output_file = ""

    def handle_data(self, packet):
        """
        Store DATA payload, send cumulative ACK.
        """
        with self.lock:
            self.received_data[packet.seq_num] = packet.payload

            # cumulative ACK
            ack_num = 0
            while ack_num in self.received_data:
                ack_num += 1

            # Send ACK
            ack_packet = Packet.get_ack_packet(packet, ack_num)
            raw = ack_packet.to_bytes()
            self.sock.sendto(raw, (ack_packet.dst_ip, ack_packet.dst_port))

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

        rcv_thread = threading.Thread(target=self.sliding_window_rcv)
        rcv_thread.daemon = True
        rcv_thread.start()
