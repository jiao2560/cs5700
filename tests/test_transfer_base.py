#!/usr/bin/env python3
"""
Unit tests for transfer_base.py
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, call
import socket
import hashlib
import time
import threading

# Import the module to test
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from transfer_base import ReliableTransferBase
from app_packet import Packet
from config import FLAG_DATA, FLAG_ACK, FLAG_FIN, FLAG_REQ


class TestReliableTransferBase(unittest.TestCase):
    """Test the ReliableTransferBase class."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a mock socket
        self.mock_sock = Mock(spec=socket.socket)
        self.dest_ip = "127.0.0.2"
        self.dest_port = 9999
        self.my_port = 8888
        self.bind_ip = "127.0.0.1"

        # Create a concrete subclass for testing (since base class is abstract)
        class TestTransfer(ReliableTransferBase):
            pass

        self.transfer = TestTransfer(
            sock=self.mock_sock,
            dest_ip=self.dest_ip,
            dest_port=self.dest_port,
            my_port=self.my_port,
            bind_ip=self.bind_ip,
        )

    def test_initialization(self):
        """Test that ReliableTransferBase initializes correctly."""
        self.assertEqual(self.transfer.sock, self.mock_sock)
        self.assertEqual(self.transfer.dest_ip, self.dest_ip)
        self.assertEqual(self.transfer.dest_port, self.dest_port)
        self.assertEqual(self.transfer.my_port, self.my_port)

        # Check sliding window state
        self.assertEqual(self.transfer.left, 0)
        self.assertEqual(self.transfer.right, 0)

        # Check lock exists
        self.assertIsInstance(self.transfer.lock, type(threading.Lock()))

        # Check metrics
        self.assertEqual(self.transfer.start_time, 0.0)
        self.assertEqual(self.transfer.end_time, 0.0)
        self.assertEqual(self.transfer.packets_sent, 0)
        self.assertEqual(self.transfer.retransmissions, 0)
        self.assertEqual(self.transfer.packets_received, 0)
        self.assertEqual(self.transfer.file_size, 0)
        self.assertTrue(self.transfer.running)

        # Check socket binding was attempted
        self.mock_sock.bind.assert_called_once_with((self.bind_ip, 0))

    def test_initialization_no_bind_ip(self):
        """Test initialization without bind_ip."""
        # Create a fresh mock socket for this test
        fresh_mock_sock = Mock(spec=socket.socket)

        class TestTransfer(ReliableTransferBase):
            pass

        transfer = TestTransfer(
            sock=fresh_mock_sock,
            dest_ip=self.dest_ip,
            dest_port=self.dest_port,
            my_port=self.my_port,
            bind_ip=None,
        )

        # Socket should not be bound when bind_ip is None
        fresh_mock_sock.bind.assert_not_called()

    def test_initialization_bind_exception(self):
        """Test initialization when socket.bind raises OSError."""
        self.mock_sock.bind.side_effect = OSError("Already bound")

        class TestTransfer(ReliableTransferBase):
            pass

        # Should not raise exception
        try:
            transfer = TestTransfer(
                sock=self.mock_sock,
                dest_ip=self.dest_ip,
                dest_port=self.dest_port,
                my_port=self.my_port,
                bind_ip=self.bind_ip,
            )
            self.assertIsNotNone(transfer)
        except OSError:
            self.fail("OSError from socket.bind should be caught")

    @patch("transfer_base.parse_packet")
    @patch("transfer_base.Packet")
    def test_sliding_window_rcv_data_packet(self, MockPacket, mock_parse_packet):
        """Test receiving a DATA packet."""
        # Create a mock parsed packet
        mock_packet = Mock(spec=Packet)
        mock_packet.dst_port = self.my_port  # Matching port
        mock_packet.flags = FLAG_DATA

        # Mock the parsing chain
        mock_parsed_dict = {"dummy": "dict"}
        mock_parse_packet.return_value = mock_parsed_dict
        MockPacket.from_dict.return_value = mock_packet

        # Mock socket.recvfrom to return data once then raise OSError to break loop
        mock_data = b"raw packet data"
        call_count = 0

        def recvfrom_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (mock_data, ("127.0.0.2", 9999))
            else:
                raise OSError("Break loop")

        self.mock_sock.recvfrom.side_effect = recvfrom_side_effect
        self.transfer.running = True

        # Call sliding_window_rcv - it should process one packet then break on OSError
        self.transfer.sliding_window_rcv()

        # Verify parse_packet was called with the data
        mock_parse_packet.assert_called_once_with(mock_data)

        # Verify Packet.from_dict was called
        MockPacket.from_dict.assert_called_once_with(mock_parsed_dict)

    @patch("transfer_base.parse_packet")
    @patch("transfer_base.Packet")
    def test_sliding_window_rcv_wrong_port(self, MockPacket, mock_parse_packet):
        """Test receiving a packet for wrong port (should be ignored)."""
        mock_packet = Mock(spec=Packet)
        mock_packet.dst_port = 12345  # Different port
        mock_packet.flags = FLAG_DATA

        mock_parsed_dict = {"dummy": "dict"}
        mock_parse_packet.return_value = mock_parsed_dict
        MockPacket.from_dict.return_value = mock_packet

        # Mock socket.recvfrom to return data once then raise OSError to break loop
        mock_data = b"data"
        call_count = 0

        def recvfrom_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (mock_data, ("127.0.0.2", 9999))
            else:
                raise OSError("Break loop")

        self.mock_sock.recvfrom.side_effect = recvfrom_side_effect
        self.transfer.running = True

        # Call sliding_window_rcv - it should parse packet then ignore due to port mismatch
        self.transfer.sliding_window_rcv()

        # Packet should be parsed but then ignored due to port mismatch
        mock_parse_packet.assert_called_once_with(mock_data)
        MockPacket.from_dict.assert_called_once_with(mock_parsed_dict)

    @patch("transfer_base.parse_packet")
    @patch("transfer_base.Packet")
    def test_sliding_window_rcv_socket_error(self, MockPacket, mock_parse_packet):
        """Test socket error breaks the receive loop."""
        self.mock_sock.recvfrom.side_effect = OSError("Socket closed")

        # Should not raise exception
        try:
            self.transfer.sliding_window_rcv()
        except OSError:
            self.fail("OSError should be caught and break loop")

    def test_default_handlers(self):
        """Test default handler methods print warnings."""
        mock_packet = Mock(spec=Packet)
        mock_packet.flags = FLAG_DATA

        # Test each default handler with patch on print
        with patch("builtins.print") as mock_print:
            # Test handle_data
            self.transfer.handle_data(mock_packet)
            mock_print.assert_called_once()
            call_args = mock_print.call_args[0][0]
            self.assertIn("ignoring DATA packet", call_args)

            mock_print.reset_mock()

            # Test handle_ack
            mock_packet.flags = FLAG_ACK
            self.transfer.handle_ack(mock_packet)
            call_args = mock_print.call_args[0][0]
            self.assertIn("ignoring ACK packet", call_args)

            mock_print.reset_mock()

            # Test handle_req
            mock_packet.flags = FLAG_REQ
            self.transfer.handle_req(mock_packet)
            call_args = mock_print.call_args[0][0]
            self.assertIn("ignoring REQ packet", call_args)

            mock_print.reset_mock()

            # Test handle_fin
            mock_packet.flags = FLAG_FIN
            self.transfer.handle_fin(mock_packet)
            call_args = mock_print.call_args[0][0]
            self.assertIn("ignoring FIN packet", call_args)

    @patch("builtins.open")
    @patch("hashlib.md5")
    def test_md5_method(self, mock_md5, mock_open):
        """Test MD5 hash computation."""
        # Setup mocks
        mock_file = Mock()
        mock_file.read.return_value = b"file contents"
        mock_open.return_value.__enter__.return_value = mock_file

        mock_hash = Mock()
        mock_hash.hexdigest.return_value = "d41d8cd98f00b204e9800998ecf8427e"
        mock_md5.return_value = mock_hash

        filepath = "test.txt"
        result = self.transfer.md5(filepath)

        # Verify file was opened correctly
        mock_open.assert_called_once_with(filepath, "rb")

        # Verify file was read
        mock_file.read.assert_called_once()

        # Verify MD5 was computed
        mock_md5.assert_called_once_with(b"file contents")

        # Verify hexdigest was called
        mock_hash.hexdigest.assert_called_once()

        # Verify result
        self.assertEqual(result, "d41d8cd98f00b204e9800998ecf8427e")

    def test_cleanup(self):
        """Test cleanup method (currently just prints)."""
        with patch("builtins.print") as mock_print:
            self.transfer.cleanup()
            mock_print.assert_called_once()
            call_args = mock_print.call_args[0][0]
            self.assertIn("cleanup called", call_args)

    def test_reset_state(self):
        """Test reset_state method."""
        # Set some state
        self.transfer.left = 5
        self.transfer.right = 10
        self.transfer.expiry_time[1] = 100.0
        self.transfer.expiry_time[2] = 200.0
        self.transfer.start_time = 1.0
        self.transfer.end_time = 2.0
        self.transfer.packets_sent = 10
        self.transfer.retransmissions = 3
        self.transfer.packets_received = 8
        self.transfer.file_size = 1024
        self.transfer.running = False

        # Reset state
        self.transfer.reset_state()

        # Verify state was reset
        self.assertEqual(self.transfer.left, 0)
        self.assertEqual(self.transfer.right, 0)
        self.assertEqual(len(self.transfer.expiry_time), 0)
        self.assertEqual(self.transfer.start_time, 0.0)
        self.assertEqual(self.transfer.end_time, 0.0)
        self.assertEqual(self.transfer.packets_sent, 0)
        self.assertEqual(self.transfer.retransmissions, 0)
        self.assertEqual(self.transfer.packets_received, 0)
        self.assertEqual(self.transfer.file_size, 0)
        self.assertTrue(self.transfer.running)

    def test_lock_usage(self):
        """Test that lock is used in reset_state."""
        # Verify lock exists and is a threading.Lock
        self.assertIsInstance(self.transfer.lock, type(threading.Lock()))

        # reset_state should work with the real lock
        self.transfer.reset_state()

        # Verify state was reset (already tested in test_reset_state)
        self.assertEqual(self.transfer.left, 0)
        self.assertEqual(self.transfer.right, 0)


if __name__ == "__main__":
    unittest.main()
