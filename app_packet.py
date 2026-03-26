import struct
from dataclasses import dataclass

HEADER_FORMAT: str = '!IIB'
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
    def from_dict(d: dict) -> 'Packet':
        """Construct from Packet object dict"""
        raw_payload: bytes = d['payload']
        seq_num, ack_num, flags = struct.unpack(HEADER_FORMAT, raw_payload[:HEADER_SIZE])

        return Packet(
            version=d['ip']['version'],
            ihl=d['ip']['ihl'],
            total_length=d['ip']['total_length'],
            ttl=d['ip']['ttl'],
            protocol=d['ip']['protocol'],
            src_ip=d['ip']['src_ip'],
            dst_ip=d['ip']['dst_ip'],
            src_port=d['udp']['src_port'],
            dst_port=d['udp']['dst_port'],
            udp_length=d['udp']['length'],
            udp_checksum=d['udp']['checksum'],
            seq_num=seq_num,
            ack_num=ack_num,
            flags=flags,
            payload=raw_payload[HEADER_SIZE:]
        )
