#!/usr/bin/env python3
"""
Unit tests for app_packet.py
"""

import unittest
from unittest.mock import patch, MagicMock
import socket
import struct
from dataclasses import asdict

# Import the module to test
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from app_packet import Packet, HEADER_SIZE, HEADER_FORMAT
from config import FLAG_DATA, FLAG_ACK, FLAG_FIN, FLAG_REQ


class TestPacket(unittest.TestCase):
    """Test the Packet dataclass and its static methods."""

    def test_packet_dataclass_creation(self):
        """Test that Packet dataclass can be instantiated with all fields."""
        packet = Packet(
            version=4,
            ihl=5,
            total_length=100,
            ttl=64,
            protocol=socket.IPPROTO_UDP,
            src_ip="127.0.0.1",
            dst_ip="127.0.0.2",
            src_port=8888,
            dst_port=9999,
            udp_length=50,
            udp_checksum=12345,
            seq_num=1,
            ack_num=2,
            flags=FLAG_DATA,
            payload=b"test payload",
        )

        self.assertEqual(packet.version, 4)
        self.assertEqual(packet.ihl, 5)
        self.assertEqual(packet.src_ip, "127.0.0.1")
        self.assertEqual(packet.dst_ip, "127.0.0.2")
        self.assertEqual(packet.seq_num, 1)
        self.assertEqual(packet.ack_num, 2)
        self.assertEqual(packet.flags, FLAG_DATA)
        self.assertEqual(packet.payload, b"test payload")
        self.assertEqual(packet.src_port, 8888)
        self.assertEqual(packet.dst_port, 9999)

    def test_get_ack_packet(self):
        """Test creation of ACK packet."""
        # Create a mock request packet
        request = Packet(
            version=4,
            ihl=5,
            total_length=100,
            ttl=64,
            protocol=socket.IPPROTO_UDP,
            src_ip="127.0.0.1",
            dst_ip="127.0.0.2",
            src_port=8888,
            dst_port=9999,
            udp_length=50,
            udp_checksum=12345,
            seq_num=0,
            ack_num=0,
            flags=FLAG_REQ,
            payload=b"test.txt",
        )

        ack_num = 5
        ack_packet = Packet.get_ack_packet(request, ack_num)

        # Verify ACK packet properties
        self.assertEqual(ack_packet.version, 4)
        self.assertEqual(ack_packet.ihl, 5)
        # Total length should be IP header (20) + UDP header (8) + app header (HEADER_SIZE)
        self.assertEqual(ack_packet.total_length, 20 + 8 + HEADER_SIZE)
        self.assertEqual(ack_packet.protocol, request.protocol)
        # ACK packet should swap src/dst from request
        self.assertEqual(ack_packet.src_ip, request.dst_ip)
        self.assertEqual(ack_packet.dst_ip, request.src_ip)
        self.assertEqual(ack_packet.src_port, request.dst_port)
        self.assertEqual(ack_packet.dst_port, request.src_port)
        self.assertEqual(ack_packet.seq_num, 0)  # ACK packets have seq_num = 0
        self.assertEqual(ack_packet.ack_num, ack_num)
        self.assertEqual(ack_packet.flags, FLAG_ACK)
        self.assertEqual(ack_packet.payload, b"")

    def test_get_data_packet(self):
        """Test creation of DATA packet with sequence number."""
        request = Packet(
            version=4,
            ihl=5,
            total_length=100,
            ttl=64,
            protocol=socket.IPPROTO_UDP,
            src_ip="127.0.0.1",
            dst_ip="127.0.0.2",
            src_port=8888,
            dst_port=9999,
            udp_length=50,
            udp_checksum=12345,
            seq_num=0,
            ack_num=0,
            flags=FLAG_REQ,
            payload=b"test.txt",
        )

        file_contents = b"file data chunk"
        seq_num = 3
        data_packet = Packet.get_data_packet(file_contents, request, seq_num)

        self.assertEqual(data_packet.version, 4)
        self.assertEqual(data_packet.ihl, 5)
        # Total length should include payload
        expected_total_len = 20 + 8 + HEADER_SIZE + len(file_contents)
        self.assertEqual(data_packet.total_length, expected_total_len)
        self.assertEqual(data_packet.protocol, request.protocol)
        # DATA packet should swap src/dst from request
        self.assertEqual(data_packet.src_ip, request.dst_ip)
        self.assertEqual(data_packet.dst_ip, request.src_ip)
        self.assertEqual(data_packet.src_port, request.dst_port)
        self.assertEqual(data_packet.dst_port, request.src_port)
        self.assertEqual(data_packet.seq_num, seq_num)
        self.assertEqual(data_packet.ack_num, 0)  # Default ack_num is 0
        self.assertEqual(data_packet.flags, FLAG_DATA)
        self.assertEqual(data_packet.payload, file_contents)

    def test_get_data_packet_with_ack_num(self):
        """Test DATA packet creation with explicit ack_num."""
        request = Packet(
            version=4,
            ihl=5,
            total_length=100,
            ttl=64,
            protocol=socket.IPPROTO_UDP,
            src_ip="127.0.0.1",
            dst_ip="127.0.0.2",
            src_port=8888,
            dst_port=9999,
            udp_length=50,
            udp_checksum=12345,
            seq_num=0,
            ack_num=0,
            flags=FLAG_REQ,
            payload=b"test.txt",
        )

        file_contents = b"data"
        seq_num = 1
        ack_num = 5
        data_packet = Packet.get_data_packet(file_contents, request, seq_num, ack_num)

        self.assertEqual(data_packet.seq_num, seq_num)
        self.assertEqual(data_packet.ack_num, ack_num)
        self.assertEqual(data_packet.flags, FLAG_DATA)

    def test_get_fin_packet(self):
        """Test creation of FIN packet with MD5 hash."""
        request = Packet(
            version=4,
            ihl=5,
            total_length=100,
            ttl=64,
            protocol=socket.IPPROTO_UDP,
            src_ip="127.0.0.1",
            dst_ip="127.0.0.2",
            src_port=8888,
            dst_port=9999,
            udp_length=50,
            udp_checksum=12345,
            seq_num=0,
            ack_num=0,
            flags=FLAG_REQ,
            payload=b"test.txt",
        )

        md5_hash = b"1234567890123456"  # 16 bytes
        fin_packet = Packet.get_fin_packet(request, md5_hash)

        expected_total_len = 20 + 8 + HEADER_SIZE + len(md5_hash)
        self.assertEqual(fin_packet.total_length, expected_total_len)
        self.assertEqual(fin_packet.protocol, request.protocol)
        # FIN packet should swap src/dst from request
        self.assertEqual(fin_packet.src_ip, request.dst_ip)
        self.assertEqual(fin_packet.dst_ip, request.src_ip)
        self.assertEqual(fin_packet.src_port, request.dst_port)
        self.assertEqual(fin_packet.dst_port, request.src_port)
        self.assertEqual(fin_packet.seq_num, 0)
        self.assertEqual(fin_packet.ack_num, 0)
        self.assertEqual(fin_packet.flags, FLAG_FIN)
        self.assertEqual(fin_packet.payload, md5_hash)

    def test_get_fin_packet_empty_md5(self):
        """Test FIN packet creation with empty MD5 hash."""
        request = Packet(
            version=4,
            ihl=5,
            total_length=100,
            ttl=64,
            protocol=socket.IPPROTO_UDP,
            src_ip="127.0.0.1",
            dst_ip="127.0.0.2",
            src_port=8888,
            dst_port=9999,
            udp_length=50,
            udp_checksum=12345,
            seq_num=0,
            ack_num=0,
            flags=FLAG_REQ,
            payload=b"test.txt",
        )

        fin_packet = Packet.get_fin_packet(request)  # Default empty bytes

        expected_total_len = 20 + 8 + HEADER_SIZE  # No MD5 hash
        self.assertEqual(fin_packet.total_length, expected_total_len)
        self.assertEqual(fin_packet.payload, b"")

    def test_get_req_packet(self):
        """Test creation of REQ packet."""
        filename = "test.txt"
        src_ip = "127.0.0.1"
        dst_ip = "127.0.0.2"
        src_port = 8888
        dst_port = 9999

        req_packet = Packet.get_req_packet(filename, src_ip, dst_ip, src_port, dst_port)

        self.assertEqual(req_packet.version, 4)
        self.assertEqual(req_packet.ihl, 5)
        expected_total_len = 20 + 8 + HEADER_SIZE + len(filename.encode())
        self.assertEqual(req_packet.total_length, expected_total_len)
        self.assertEqual(req_packet.protocol, socket.IPPROTO_UDP)
        self.assertEqual(req_packet.src_ip, src_ip)
        self.assertEqual(req_packet.dst_ip, dst_ip)
        self.assertEqual(req_packet.src_port, src_port)
        self.assertEqual(req_packet.dst_port, dst_port)
        self.assertEqual(req_packet.seq_num, 0)
        self.assertEqual(req_packet.ack_num, 0)
        self.assertEqual(req_packet.flags, FLAG_REQ)
        self.assertEqual(req_packet.payload, filename.encode())

    def test_from_dict(self):
        """Test constructing Packet from dictionary (parsed packet)."""
        # Create a dictionary matching parse_packet output format
        packet_dict = {
            "ip": {
                "version": 4,
                "ihl": 5,
                "total_length": 100,
                "ttl": 64,
                "protocol": socket.IPPROTO_UDP,
                "src_ip": "127.0.0.1",
                "dst_ip": "127.0.0.2",
            },
            "udp": {
                "src_port": 8888,
                "dst_port": 9999,
                "length": 50,
                "checksum": 12345,
            },
            "payload": struct.pack(HEADER_FORMAT, 1, 2, FLAG_DATA) + b"app payload",
        }

        packet = Packet.from_dict(packet_dict)

        self.assertEqual(packet.version, 4)
        self.assertEqual(packet.ihl, 5)
        self.assertEqual(packet.total_length, 100)
        self.assertEqual(packet.ttl, 64)
        self.assertEqual(packet.protocol, socket.IPPROTO_UDP)
        self.assertEqual(packet.src_ip, "127.0.0.1")
        self.assertEqual(packet.dst_ip, "127.0.0.2")
        self.assertEqual(packet.src_port, 8888)
        self.assertEqual(packet.dst_port, 9999)
        self.assertEqual(packet.udp_length, 50)
        self.assertEqual(packet.udp_checksum, 12345)
        self.assertEqual(packet.seq_num, 1)
        self.assertEqual(packet.ack_num, 2)
        self.assertEqual(packet.flags, FLAG_DATA)
        self.assertEqual(packet.payload, b"app payload")

    @patch("app_packet.build_packet")
    def test_to_bytes(self, mock_build_packet):
        """Test converting Packet to bytes."""
        mock_build_packet.return_value = b"mock raw packet"

        packet = Packet(
            version=4,
            ihl=5,
            total_length=100,
            ttl=64,
            protocol=socket.IPPROTO_UDP,
            src_ip="127.0.0.1",
            dst_ip="127.0.0.2",
            src_port=8888,
            dst_port=9999,
            udp_length=50,
            udp_checksum=12345,
            seq_num=1,
            ack_num=2,
            flags=FLAG_DATA,
            payload=b"test payload",
        )

        result = packet.to_bytes()

        # Verify build_packet was called with correct arguments
        mock_build_packet.assert_called_once()

        # Check keyword arguments (build_packet uses keyword args)
        call_kwargs = mock_build_packet.call_args.kwargs

        # The payload should be app_header + original payload
        expected_app_header = struct.pack(
            HEADER_FORMAT, packet.seq_num, packet.ack_num, packet.flags
        )
        expected_app_data = expected_app_header + packet.payload

        self.assertEqual(call_kwargs["src_ip"], packet.src_ip)
        self.assertEqual(call_kwargs["dst_ip"], packet.dst_ip)
        self.assertEqual(call_kwargs["src_port"], packet.src_port)
        self.assertEqual(call_kwargs["dst_port"], packet.dst_port)
        self.assertEqual(call_kwargs["payload"], expected_app_data)

        # Verify returned value
        self.assertEqual(result, b"mock raw packet")

    def test_flag_constants(self):
        """Verify flag constants match expected values."""
        self.assertEqual(FLAG_DATA, 0)
        self.assertEqual(FLAG_ACK, 1)
        self.assertEqual(FLAG_FIN, 2)
        self.assertEqual(FLAG_REQ, 3)

    def test_header_size_calculation(self):
        """Verify HEADER_SIZE matches struct format."""
        # HEADER_FORMAT is "!IIB" = 4 + 4 + 1 = 9 bytes
        expected_size = struct.calcsize("!IIB")
        self.assertEqual(HEADER_SIZE, expected_size)
        self.assertEqual(HEADER_SIZE, 9)  # 4 + 4 + 1 = 9 bytes


if __name__ == "__main__":
    unittest.main()
