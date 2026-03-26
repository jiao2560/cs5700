from mock_packet import *

import threading
import socket
import time
from collections import defaultdict
from config import *
from app_packet import Packet


class ReliableTransfer:
    """
    Reliable file transfer over raw UDP sockets.
    Usage:
        # Server (sender)
        rt = ReliableTransfer(sock, dest_ip, dest_port, role='sender')
        report = rt.send_file('photo.jpg')

        # Client (receiver)  
        rt = ReliableTransfer(sock, dest_ip, dest_port, role='receiver')
        report = rt.receive_file('output.jpg')
    """

    def __init__(self, sock, dest_ip, dest_port):
        self.sock = sock
        self.dest_ip = dest_ip
        self.dest_port = dest_port

        self.left, self.right = 0, 0
        self.lock = threading.Lock()

        self.send_buff: list[Packet] = []
        self.sent_buff: list[Packet] = []
        self.expiry_time: dict[Packet, float] = defaultdict(float)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)


    def sliding_window_send(self):
        while True:
            with self.lock:
                buff, r, l = self.send_buff, self.right, self.left

            # Expand the window
            while buff and r - l < WINDOW_SIZE:
                # send packet
                with self.lock:
                    packet = self.send_buff.pop(0)
                    try:
                        self.sock.sendto(packet.payload, (packet.src_ip, packet.dst_ip))
                        self.expiry_time[packet] = time.monotonic() + TIMEOUT
                        self.right = packet.seq_num
                    except:
                        self.send_buff.append(packet) # Try again later

            # Try to retransmit packets that are expired
            with self.lock:
                for pac in self.sent_buff:
                    if time.monotonic() > self.expiry_time[pac]:
                        self.sock.sendto(pac.payload, (pac.src_ip, pac.dst_ip))
                        self.expiry_time[pac] = time.monotonic() + TIMEOUT



    def sliding_window_rcv(self):

        self.sock.bind((SERVER_IP, SERVER_PORT))

        while True:
            data, addr = self.sock.recvfrom(65535)
            parsed = Packet.from_dict(parse_packet(data))

            if parsed.flags == FLAG_DATA:
                with self.lock:
                    # TODO: unpack the struct here, parse out the requested filename, serve it
                    data = 
                    # This is the file sent out in chuncks from server side, and 
            elif parsed.flags == FLAG_ACK:
                with self.lock:
                    self.left == parsed.seq_num
                    self.sent_buff.remove(parsed)

    def transfer_file(self):
        #TODO:
        ...



