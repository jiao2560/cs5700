import threading
import hashlib
import time
from collections import defaultdict
from config import *
from packet import *
from app_packet import Packet, HEADER_SIZE


class ReliableTransfer:
    """
    # Server side — waits for a request, then sends
    rt = ReliableTransfer(sock, role='sender')
    report = rt.listen_and_serve()  # listens for REQ, then sends the file

    # Client side — requests a file, then receives
    rt = ReliableTransfer(sock, dest_ip, dest_port, role='receiver')
    report = rt.request_file('photo.jpg', 'output.jpg')
    """

    def __init__(self, sock, dest_ip, dest_port, role):
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.role = role
        self.my_port = SERVER_PORT if role == "sender" else CLIENT_PORT
        self.sock = sock

        self.left, self.right = 0, 0
        self.lock = threading.Lock()

        self.send_buff = []
        self.sent_buff = []
        self.expiry_time = defaultdict(float)
        self.recv_buff = {}
        self.received_packets = []
        self.requested_file: str = ""

    def sliding_window_send(self):
        """
        Meant to be run in a separate thread. Continually tries to send packets in the send buffer.
        Maintains a sliding window and retransmits after timeout
        """
        while True:
            with self.lock:
                if self.send_buff and self.right - self.left < WINDOW_SIZE:
                    packet = self.send_buff.pop(0)
                    try:
                        raw = packet.to_bytes()
                        self.sock.sendto(raw, (packet.dst_ip, packet.dst_port))
                        self.sent_buff.append(packet)
                        self.expiry_time[packet.seq_num] = time.monotonic() + TIMEOUT
                        if packet.seq_num >= self.right:
                            self.right = packet.seq_num + 1
                    except:
                        self.send_buff.insert(0, packet)

            with self.lock:
                now = time.monotonic()
                for pac in self.sent_buff:
                    exp = self.expiry_time.get(pac.seq_num)
                    if exp and now > exp:
                        raw = pac.to_bytes()
                        self.sock.sendto(raw, (pac.dst_ip, pac.dst_port))
                        self.expiry_time[pac.seq_num] = now + TIMEOUT

    def sliding_window_rcv(self):
        while True:
            data, _ = self.sock.recvfrom(65535)
            parsed = Packet.from_dict(parse_packet(data))
            if parsed.dst_port != self.my_port:
                continue

            if parsed.flags == FLAG_DATA: # Client receives this
                with self.lock:
                    self.recv_buff[parsed.seq_num] = parsed.payload
                    if self.role == "receiver":
                        ack_num = 0
                        while ack_num in self.recv_buff:
                            ack_num += 1
                        ack_packet = Packet.get_ack_packet(parsed, ack_num)
                        raw = ack_packet.to_bytes()
                        self.sock.sendto(raw, (ack_packet.dst_ip, ack_packet.dst_port))

            elif parsed.flags == FLAG_ACK: # Server receives this
                with self.lock:
                    self.left = parsed.ack_num
                    to_remove = [
                        p for p in self.sent_buff if p.seq_num < parsed.ack_num
                    ]
                    for p in to_remove:
                        self.expiry_time.pop(p.seq_num, None)
                    self.sent_buff = [
                        p for p in self.sent_buff if p.seq_num >= parsed.ack_num
                    ]
            elif parsed.flags == FLAG_REQ: # Server receives this
                self.requested_file = str(parsed.payload)
                self.transfer_file(self.requested_file, parsed)
            elif parsed.flags == FLAG_FIN: # Client receives this
                self.assemble_file()
                self.cleanup()

    def cleanup(self):
        #TODO: Close sockets used and any other cleanup
        #TODO: Write the output stub
        ...

    def transfer_file(self, file_path: str, req: Packet) -> None:
        try:
            with open(file_path, "rb") as f:
                dat, i = f.read(), 0
                while i + MAX_PAYLOAD_SIZE < len(dat):
                    # Send a max payload sized file chunk
                    self.send_buff.append(Packet.get_data_packet(dat[i:i + MAX_PAYLOAD_SIZE], req, seq_num=i))
                    i += MAX_PAYLOAD_SIZE

        except Exception as e:
            print(f"Encounted {e} while trying to read file {file_path}")

    def assemble_file(self) -> None:
        file: bytes = b""

        for p in self.received_packets:
            if p.flags == FLAG_DATA:
                file += p.payload

        with open(self.requested_file, "wb") as f:
            f.write(file)

    def md5(self, filepath):
        with open(filepath, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()

    def listen_and_serve(self) -> None:
        """
        Server side implementation of reliable transfer. Spawns threads with the send and receive logic.
        """
        send_thread = threading.Thread(target=self.sliding_window_send)
        rcv_thread = threading.Thread(target=self.sliding_window_rcv)
        send_thread.daemon = True # cleanup when the main thread exits
        rcv_thread.daemon = True

        send_thread.start()
        rcv_thread.start()

