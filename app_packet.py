import socket
import struct
from dataclasses import dataclass
from packet import build_packet
from config import *

HEADER_FORMAT: str = "!IIB"  # seq, ack, flags
HEADER_SIZE: int = struct.calcsize(HEADER_FORMAT)


@dataclass
class Packet:
    """
    Complete packet representation combining network layer fields
    and application protocol fields.
    """

    # IP
    version: int
    ihl: int
    total_length: int
    ttl: int
    protocol: int
    src_ip: str
    dst_ip: str

    # UDP
    src_port: int
    dst_port: int
    udp_length: int
    udp_checksum: int

    # Application protocol
    seq_num: int
    ack_num: int
    flags: int

    payload: bytes

    @staticmethod
    def get_ack_packet(request: "Packet", ack_num: int) -> "Packet":
        return Packet(
            version=4,
            ihl=5,
            total_length=20 + 8 + HEADER_SIZE,
            ttl=64,
            protocol=request.protocol,
            src_ip=request.dst_ip,
            dst_ip=request.src_ip,
            src_port=request.dst_port,
            dst_port=request.src_port,
            udp_length=8 + HEADER_SIZE,
            udp_checksum=0,
            seq_num=0,
            ack_num=ack_num,
            flags=FLAG_ACK,
            payload=b"",
        )

    @staticmethod
    def get_data_packet(
        file_contents: bytes, request: "Packet", seq_num: int = 0, ack_num: int = 0
    ) -> "Packet":
        payload_len = len(file_contents)
        return Packet(
            version=4,
            ihl=5,
            total_length=20 + 8 + HEADER_SIZE + payload_len,
            ttl=64,
            protocol=request.protocol,
            src_ip=request.dst_ip,
            dst_ip=request.src_ip,
            src_port=request.dst_port,
            dst_port=request.src_port,
            udp_length=8 + HEADER_SIZE + payload_len,
            udp_checksum=0,
            seq_num=seq_num,
            ack_num=ack_num,
            flags=FLAG_DATA,
            payload=file_contents,
        )

    @staticmethod
    def get_fin_packet(request: "Packet", md5_hash: bytes = b"") -> "Packet":
        return Packet(
            version=4,
            ihl=5,
            total_length=20 + 8 + HEADER_SIZE + len(md5_hash),
            ttl=64,
            protocol=request.protocol,
            src_ip=request.dst_ip,
            dst_ip=request.src_ip,
            src_port=request.dst_port,
            dst_port=request.src_port,
            udp_length=8 + HEADER_SIZE + len(md5_hash),
            udp_checksum=0,
            seq_num=0,
            ack_num=0,
            flags=FLAG_FIN,
            payload=md5_hash,
        )

    @staticmethod
    def get_req_packet(
        filename: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int
    ) -> "Packet":
        """Create a REQ packet from client to server."""
        payload = filename.encode()
        return Packet(
            version=4,
            ihl=5,
            total_length=20 + 8 + HEADER_SIZE + len(payload),
            ttl=64,
            protocol=socket.IPPROTO_UDP,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            udp_length=8 + HEADER_SIZE + len(payload),
            udp_checksum=0,
            seq_num=0,
            ack_num=0,
            flags=FLAG_REQ,
            payload=payload,
        )

    @staticmethod
    def from_dict(d: dict) -> "Packet":
        """Construct from Packet object dict"""
        raw_payload: bytes = d["payload"]
        seq_num, ack_num, flags = struct.unpack(
            HEADER_FORMAT, raw_payload[:HEADER_SIZE]
        )

        return Packet(
            version=d["ip"]["version"],
            ihl=d["ip"]["ihl"],
            total_length=d["ip"]["total_length"],
            ttl=d["ip"]["ttl"],
            protocol=d["ip"]["protocol"],
            src_ip=d["ip"]["src_ip"],
            dst_ip=d["ip"]["dst_ip"],
            src_port=d["udp"]["src_port"],
            dst_port=d["udp"]["dst_port"],
            udp_length=d["udp"]["length"],
            udp_checksum=d["udp"]["checksum"],
            seq_num=seq_num,
            ack_num=ack_num,
            flags=flags,
            payload=raw_payload[HEADER_SIZE:],
        )

    def to_bytes(self) -> bytes:
        """
        Encode packet into raw bytes using Person A's build_packet.
        Packs the application header (seq, ack, flags) + payload,
        then delegates IP/UDP construction to packet.py.
        """

        app_header: bytes = struct.pack(
            HEADER_FORMAT, self.seq_num, self.ack_num, self.flags
        )
        app_data: bytes = app_header + self.payload

        return build_packet(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            payload=app_data,
        )
