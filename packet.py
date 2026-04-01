"""
packet.py

This module provides low-level packet utilities for the SRFT project.

Functions included:
- compute_checksum(data)
- build_ip_header(src_ip, dst_ip, total_length)
- build_udp_header(src_port, dst_port, payload)
- build_packet(src_ip, dst_ip, src_port, dst_port, payload)
- parse_packet(raw_bytes)

This module is the foundation for later reliable transfer features.
"""


import struct
import socket


def compute_checksum(data: bytes) -> int:
    """
    Compute the checksum of the given data using the Internet Checksum algorithm.

    - If the data length is odd, pad with one zero byte.
    - Sum all 16-bit words.
    - Add carry bits back into the lower 16 bits.
    - Take one's complement of the final sum.
    """
    if len(data) % 2 == 1:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)

    checksum = ~checksum & 0xffff
    return checksum


def build_ip_header(src_ip: str, dst_ip: str, total_length: int) -> bytes:
    """
    Build a basic IPv4 header (20 bytes).

    Parameters:
    - src_ip: source IP address (string)
    - dst_ip: destination IP address (string)
    - total_length: total length of the packet (IP header + UDP header + payload)

    Returns:
    - Packed IP header in bytes
    """

    version = 4
    ihl = 5  # Internet Header Length (5 * 4 = 20 bytes)
    ver_ihl = (version << 4) + ihl

    tos = 0  # Type of Service
    identification = 54321
    flags_fragment_offset = 0
    ttl = 64  # Time to Live
    protocol = socket.IPPROTO_UDP  # UDP protocol
    header_checksum = 0  # set to 0 for now

    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        tos,
        total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        header_checksum,
        src_addr,
        dst_addr
    )

    return ip_header


def build_udp_header(src_port: int, dst_port: int, payload: bytes) -> bytes:
    """
    Build a UDP header (8 bytes).

    Parameters:
    - src_port: source port
    - dst_port: destination port
    - payload: data in bytes

    Returns:
    - Packed UDP header in bytes
    """

    udp_length = 8 + len(payload)
    checksum = 0

    # First pack the header with checksum = 0
    udp_header = struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        udp_length,
        checksum
    )

    # Compute checksum over UDP header + payload
    checksum_data = udp_header + payload
    checksum = compute_checksum(checksum_data)

    # Re-pack the header with the real checksum
    udp_header = struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        udp_length,
        checksum
    )

    return udp_header


def build_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes
) -> bytes:
    """
    Build a complete packet:
    [IP header][UDP header][payload]

    Parameters:
    - src_ip: source IP address
    - dst_ip: destination IP address
    - src_port: source port
    - dst_port: destination port
    - payload: data in bytes

    Returns:
    - Complete packet in bytes
    """

    udp_header = build_udp_header(src_port, dst_port, payload)
    total_length = 20 + len(udp_header) + len(payload)
    ip_header = build_ip_header(src_ip, dst_ip, total_length)

    packet = ip_header + udp_header + payload
    return packet


def parse_packet(raw_bytes: bytes) -> dict:
    """
    Parse a raw packet into IP header, UDP header, and payload.

    Parameters:
    - raw_bytes: complete packet in bytes

    Returns:
    - A dictionary containing parsed IP fields, UDP fields, and payload
    """

    # Parse IP header (first 20 bytes)
    ip_header = raw_bytes[:20]
    ip_fields = struct.unpack("!BBHHHBBH4s4s", ip_header)

    ver_ihl = ip_fields[0]
    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F
    ip_header_length = ihl * 4

    total_length = ip_fields[2]
    ttl = ip_fields[5]
    protocol = ip_fields[6]
    src_ip = socket.inet_ntoa(ip_fields[8])
    dst_ip = socket.inet_ntoa(ip_fields[9])

    # Parse UDP header
    udp_start = ip_header_length
    udp_end = udp_start + 8
    udp_header = raw_bytes[udp_start:udp_end]
    udp_fields = struct.unpack("!HHHH", udp_header)

    src_port = udp_fields[0]
    dst_port = udp_fields[1]
    udp_length = udp_fields[2]
    udp_checksum = udp_fields[3]

    # Extract payload
    payload = raw_bytes[udp_end:udp_start + udp_length]

    return {
        "ip": {
            "version": version,
            "ihl": ihl,
            "total_length": total_length,
            "ttl": ttl,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        },
        "udp": {
            "src_port": src_port,
            "dst_port": dst_port,
            "length": udp_length,
            "checksum": udp_checksum,
        },
        "payload": payload
    }


def build_packet_simple(data: bytes) -> bytes:
    """
    Simple wrapper for future extension (Person B compatibility)
    """
    from config import CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT

    return build_packet(
        src_ip=CLIENT_IP,
        dst_ip=SERVER_IP,
        src_port=CLIENT_PORT,
        dst_port=SERVER_PORT,
        payload=data
    )

