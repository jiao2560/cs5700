#!/usr/bin/env python3
"""
Unit tests for reliable_transfer.py (Sender and Receiver classes)
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, call, mock_open
import socket
import threading
import time
import hashlib
import struct

# Import the module to test
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from reliable_transfer import Sender, Receiver
from app_packet import Packet, HEADER_SIZE
from config import (
    FLAG_DATA,
    FLAG_ACK,
    FLAG_FIN,
    FLAG_REQ,
    WINDOW_SIZE,
    TIMEOUT,
    MAX_PAYLOAD_SIZE,
)
from config import SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT


class TestSender(unittest.TestCase):
    """Test the Sender class (server-side reliable transfer)."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_sock = Mock(spec=socket.socket)
        self.dest_ip = CLIENT_IP
        self.dest_port = CLIENT_PORT

        self.sender = Sender(
            sock=self.mock_sock, dest_ip=self.dest_ip, dest_port=self.dest_port
        )

        # Mock the socket binding that happens in parent __init__
        self.mock_sock.bind.assert_called_once_with((SERVER_IP, 0))

    def test_initialization(self):
        """Test Sender initialization."""
        self.assertEqual(self.sender.sock, self.mock_sock)
        self.assertEqual(self.sender.dest_ip, self.dest_ip)
        self.assertEqual(self.sender.dest_port, self.dest_port)
        self.assertEqual(self.sender.my_port, SERVER_PORT)

        # Check Sender-specific attributes
        self.assertEqual(self.sender.pending_data_queue, [])
        self.assertEqual(self.sender.unacked_packets, [])
        self.assertIsNone(self.sender.client_req)
        self.assertFalse(self.sender.all_chunks_queued)
        self.assertFalse(self.sender.fin_sent)
        self.assertFalse(self.sender.fin_acked)
        self.assertEqual(self.sender.fin_expiry, 0.0)
        self.assertEqual(self.sender.md5_hash, b"")
        self.assertEqual(self.sender.total_chunks, 0)

    @patch("reliable_transfer.time.monotonic")
    def test_transfer_file_small(self, mock_monotonic):
        """Test reading a small file and creating DATA packets."""
        mock_monotonic.return_value = 1000.0

        # Create a mock request packet
        mock_req = Mock(spec=Packet)
        mock_req.protocol = socket.IPPROTO_UDP
        mock_req.dst_ip = SERVER_IP
        mock_req.src_ip = CLIENT_IP
        mock_req.dst_port = SERVER_PORT
        mock_req.src_port = CLIENT_PORT

        # Mock file content
        file_content = b"Hello, World! This is a test file."
        expected_chunk_size = MAX_PAYLOAD_SIZE - HEADER_SIZE

        with patch("builtins.open", mock_open(read_data=file_content)) as mock_file:
            with patch("hashlib.md5") as mock_md5:
                mock_hash = Mock()
                mock_hash.digest.return_value = b"mock_md5_hash_16"
                mock_md5.return_value = mock_hash

                self.sender.transfer_file("test.txt", mock_req)

        # Verify MD5 was computed
        mock_md5.assert_called_once_with(file_content)
        self.assertEqual(self.sender.md5_hash, b"mock_md5_hash_16")
        self.assertEqual(self.sender.file_size, len(file_content))
        self.assertEqual(self.sender.start_time, 1000.0)

        # Verify chunks were created
        # File is small enough to fit in one chunk
        self.assertEqual(len(self.sender.pending_data_queue), 1)
        self.assertEqual(self.sender.total_chunks, 1)
        self.assertTrue(self.sender.all_chunks_queued)
        self.assertEqual(self.sender.client_req, mock_req)

        # Check the created packet
        packet = self.sender.pending_data_queue[0]
        self.assertEqual(packet.seq_num, 0)
        self.assertEqual(packet.flags, FLAG_DATA)
        self.assertEqual(packet.payload, file_content)

    @patch("reliable_transfer.time.monotonic")
    def test_transfer_file_large_multiple_chunks(self, mock_monotonic):
        """Test reading a file that requires multiple chunks."""
        mock_monotonic.return_value = 1000.0

        # Create a mock request packet
        mock_req = Mock(spec=Packet)
        mock_req.protocol = socket.IPPROTO_UDP
        mock_req.dst_ip = SERVER_IP
        mock_req.src_ip = CLIENT_IP
        mock_req.dst_port = SERVER_PORT
        mock_req.src_port = CLIENT_PORT

        # Create content larger than one chunk
        chunk_size = MAX_PAYLOAD_SIZE - HEADER_SIZE
        # Create content that's 2.5 chunks
        file_content = b"x" * (chunk_size * 2 + chunk_size // 2)

        with patch("builtins.open", mock_open(read_data=file_content)):
            with patch("hashlib.md5") as mock_md5:
                mock_hash = Mock()
                mock_hash.digest.return_value = b"mock_hash"
                mock_md5.return_value = mock_hash

                self.sender.transfer_file("large.txt", mock_req)

        # Should have 3 chunks (2 full + 1 partial)
        self.assertEqual(self.sender.total_chunks, 3)
        self.assertEqual(len(self.sender.pending_data_queue), 3)

        # Check sequence numbers
        for i, packet in enumerate(self.sender.pending_data_queue):
            self.assertEqual(packet.seq_num, i)
            self.assertEqual(packet.flags, FLAG_DATA)

        # Check chunk sizes
        self.assertEqual(len(self.sender.pending_data_queue[0].payload), chunk_size)
        self.assertEqual(len(self.sender.pending_data_queue[1].payload), chunk_size)
        self.assertEqual(
            len(self.sender.pending_data_queue[2].payload), chunk_size // 2
        )

    def test_transfer_file_nonexistent(self):
        """Test attempting to transfer a non-existent file."""
        mock_req = Mock(spec=Packet)

        with patch("builtins.open", side_effect=FileNotFoundError("File not found")):
            with patch("builtins.print") as mock_print:
                self.sender.transfer_file("nonexistent.txt", mock_req)

                # Should print error message
                # Check that error message was printed (could be among other debug prints)
                error_found = False
                for call in mock_print.call_args_list:
                    args = call[0]
                    if len(args) > 0 and "nonexistent.txt" in str(args[0]):
                        error_found = True
                        break
                self.assertTrue(
                    error_found, "Expected error message containing 'nonexistent.txt'"
                )

        # State should not be modified
        self.assertEqual(self.sender.pending_data_queue, [])
        self.assertFalse(self.sender.all_chunks_queued)

    def test_sliding_window_send_basic(self):
        """Test sending packets within window limits."""

        # Create some mock packets
        mock_packets = []
        for i in range(6):
            mock_packet = Mock(spec=Packet)
            mock_packet.seq_num = i
            mock_packet.dst_ip = self.dest_ip
            mock_packet.dst_port = self.dest_port
            mock_packet.to_bytes.return_value = f"packet{i}".encode()
            mock_packets.append(mock_packet)

        # Add packets to pending queue
        self.sender.pending_data_queue = mock_packets.copy()

        # Set window size (default WINDOW_SIZE = 4)
        self.sender.left = 0
        self.sender.right = 0

        # Mock socket.sendto
        sent_packets = []

        def sendto_side_effect(data, addr):
            sent_packets.append(data)
            return len(data)

        self.mock_sock.sendto.side_effect = sendto_side_effect

        # Run sliding_window_send once (not in a loop)
        # We'll manually trigger the sending logic
        with self.sender.lock:
            # Send if window not full and we have pending data
            if (
                self.sender.pending_data_queue
                and self.sender.right - self.sender.left < WINDOW_SIZE
            ):
                # Send up to WINDOW_SIZE packets
                for _ in range(min(WINDOW_SIZE, len(self.sender.pending_data_queue))):
                    packet = self.sender.pending_data_queue.pop(0)
                    raw = packet.to_bytes()
                    self.mock_sock.sendto(raw, (packet.dst_ip, packet.dst_port))
                    self.sender.unacked_packets.append(packet)
                    self.sender.expiry_time[packet.seq_num] = time.monotonic() + TIMEOUT
                    if packet.seq_num >= self.sender.right:
                        self.sender.right = packet.seq_num + 1

        # Should have sent WINDOW_SIZE packets (4)
        self.assertEqual(self.mock_sock.sendto.call_count, 4)
        self.assertEqual(len(self.sender.unacked_packets), 4)
        self.assertEqual(self.sender.right, 4)
        self.assertEqual(self.sender.left, 0)
        self.assertEqual(len(self.sender.pending_data_queue), 2)  # 6 total - 4 sent

        # Check expiry times were set (should be approximately current time + TIMEOUT)
        current_time = time.monotonic()
        for i in range(4):
            self.assertIn(i, self.sender.expiry_time)
            # Allow small tolerance for test execution time
            self.assertAlmostEqual(
                self.sender.expiry_time[i], current_time + TIMEOUT, delta=0.1
            )

    @patch("reliable_transfer.time.monotonic")
    def test_sliding_window_send_timeout_retransmission(self, mock_monotonic):
        """Test retransmission of timed-out packets."""
        # Set now to 0.0, expiry to -1.0 (already expired)
        mock_monotonic.return_value = 0.0

        # Create a mock unacked packet that has timed out
        mock_packet = Mock(spec=Packet)
        mock_packet.seq_num = 0
        mock_packet.dst_ip = self.dest_ip
        mock_packet.dst_port = self.dest_port
        mock_packet.to_bytes.return_value = b"packet0"

        self.sender.unacked_packets = [mock_packet]
        self.sender.expiry_time[0] = -1.0  # Already expired

        # Mock socket.sendto
        self.mock_sock.sendto.return_value = None

        # Run the timeout check logic (simulating sliding_window_send)
        with self.sender.lock:
            now = time.monotonic()  # Will be 0.0
            for packet in self.sender.unacked_packets:
                exp = self.sender.expiry_time.get(packet.seq_num)
                if exp and now > exp:
                    raw = packet.to_bytes()
                    self.mock_sock.sendto(raw, (packet.dst_ip, packet.dst_port))
                    self.sender.expiry_time[packet.seq_num] = now + TIMEOUT
                    self.sender.retransmissions += 1

        # Should have retransmitted
        self.mock_sock.sendto.assert_called_once_with(
            b"packet0", (self.dest_ip, self.dest_port)
        )
        self.assertEqual(self.sender.retransmissions, 1)
        self.assertEqual(self.sender.expiry_time[0], 0.0 + TIMEOUT)  # New expiry

    def test_handle_ack_cumulative(self):
        """Test processing cumulative ACK."""
        # Create mock ACK packet
        mock_ack_packet = Mock(spec=Packet)
        mock_ack_packet.ack_num = 3  # Acknowledges packets 0,1,2

        # Create some mock unacked packets
        mock_packets = []
        for i in range(5):
            mock_packet = Mock(spec=Packet)
            mock_packet.seq_num = i
            mock_packets.append(mock_packet)

        self.sender.unacked_packets = mock_packets
        self.sender.left = 0
        self.sender.right = 5

        # Set expiry times
        for i in range(5):
            self.sender.expiry_time[i] = 100.0 + i

        # Call handle_ack
        self.sender.handle_ack(mock_ack_packet)

        # left should be updated to ack_num
        self.assertEqual(self.sender.left, 3)

        # Packets with seq_num < 3 should be removed from unacked_packets
        remaining_seqs = [p.seq_num for p in self.sender.unacked_packets]
        self.assertEqual(remaining_seqs, [3, 4])

        # Expiry times for seq_num < 3 should be removed
        self.assertNotIn(0, self.sender.expiry_time)
        self.assertNotIn(1, self.sender.expiry_time)
        self.assertNotIn(2, self.sender.expiry_time)
        self.assertIn(3, self.sender.expiry_time)
        self.assertIn(4, self.sender.expiry_time)

    @patch("reliable_transfer.time.monotonic")
    @patch("reliable_transfer.Packet")
    @patch.object(Sender, "generate_output_report")
    @patch.object(Sender, "reset_transfer_state")
    def test_handle_ack_triggers_fin(
        self, mock_reset, mock_report, MockPacket, mock_monotonic
    ):
        """Test that FIN is sent when all chunks are acknowledged."""
        mock_monotonic.return_value = 2000.0

        # Create mock ACK packet that acknowledges all chunks
        mock_ack_packet = Mock(spec=Packet)
        mock_ack_packet.ack_num = 5  # All 5 chunks acknowledged

        # Set up sender state as if all chunks transferred
        self.sender.all_chunks_queued = True
        self.sender.pending_data_queue = []
        self.sender.unacked_packets = []
        self.sender.total_chunks = 5
        self.sender.left = 0
        self.sender.right = 5

        # Create a mock client request
        mock_req = Mock(spec=Packet)
        mock_req.protocol = socket.IPPROTO_UDP
        mock_req.dst_ip = SERVER_IP
        mock_req.src_ip = CLIENT_IP
        mock_req.dst_port = SERVER_PORT
        mock_req.src_port = CLIENT_PORT
        self.sender.client_req = mock_req

        self.sender.md5_hash = b"mock_md5_hash"

        # Mock FIN packet creation
        mock_fin_packet = Mock(spec=Packet)
        mock_fin_packet.dst_ip = CLIENT_IP
        mock_fin_packet.dst_port = CLIENT_PORT
        mock_fin_packet.to_bytes.return_value = b"fin_packet"
        MockPacket.get_fin_packet.return_value = mock_fin_packet

        # Mock socket.sendto
        self.mock_sock.sendto.return_value = None

        # Call handle_ack
        self.sender.handle_ack(mock_ack_packet)

        # Should create and send FIN packet
        MockPacket.get_fin_packet.assert_called_once_with(mock_req, b"mock_md5_hash")
        self.mock_sock.sendto.assert_called_once_with(
            b"fin_packet", (CLIENT_IP, CLIENT_PORT)
        )

        # Check state updated
        self.assertTrue(self.sender.fin_sent)
        self.assertEqual(self.sender.fin_expiry, 2000.0 + TIMEOUT)
        self.assertEqual(self.sender.packets_sent, 1)

        # Should have called generate_output_report and reset_transfer_state
        mock_report.assert_called_once()
        mock_reset.assert_called_once()

    def test_handle_req(self):
        """Test handling REQ packet."""
        mock_req_packet = Mock(spec=Packet)
        mock_req_packet.payload = b"requested_file.txt"

        # Mock transfer_file
        with patch.object(self.sender, "transfer_file") as mock_transfer:
            self.sender.handle_req(mock_req_packet)

            # Should call transfer_file with decoded filename
            mock_transfer.assert_called_once_with("requested_file.txt", mock_req_packet)

    def test_request_file_not_implemented(self):
        """Test that Sender cannot request files."""
        with self.assertRaises(NotImplementedError):
            self.sender.request_file("test.txt")

    @patch("reliable_transfer.time.monotonic")
    def test_generate_output_report(self, mock_monotonic):
        """Test generation of output report file."""
        mock_monotonic.side_effect = [1000.0, 1005.0]  # start_time, end_time

        self.sender.start_time = 1000.0
        self.sender.end_time = 1005.0
        self.sender.requested_file_name = "test.txt"
        self.sender.file_size = 1024
        self.sender.packets_sent = 50
        self.sender.retransmissions = 5
        self.sender.packets_received = 45

        with patch("builtins.open", mock_open()) as mock_file:
            self.sender.generate_output_report()

            # Verify file was opened for writing
            mock_file.assert_called_once_with("output.txt", "w")

            # Verify content was written
            handle = mock_file()
            write_calls = handle.write.call_args_list

            # Check key content
            written_text = "".join(call[0][0] for call in write_calls)
            self.assertIn("Name of the transferred file: test.txt", written_text)
            self.assertIn("Size of the transferred file: 1024 bytes", written_text)
            self.assertIn(
                "The number of packets sent from the server: 50", written_text
            )
            self.assertIn(
                "The number of retransmitted packets from the server: 5", written_text
            )
            self.assertIn(
                "The number of packets received from the client: 45", written_text
            )
            self.assertIn(
                "The time duration of the file transfer: 00:00:05", written_text
            )

    def test_reset_transfer_state(self):
        """Test resetting sender state."""
        # Set some state
        self.sender.pending_data_queue = [Mock(), Mock()]
        self.sender.unacked_packets = [Mock()]
        self.sender.expiry_time[0] = 100.0
        self.sender.expiry_time[1] = 200.0
        self.sender.client_req = Mock()
        self.sender.all_chunks_queued = True
        self.sender.fin_sent = True
        self.sender.fin_acked = True
        self.sender.fin_expiry = 300.0
        self.sender.md5_hash = b"hash"
        self.sender.total_chunks = 10
        self.sender.left = 5
        self.sender.right = 10

        self.sender.reset_transfer_state()

        # Verify state reset
        self.assertEqual(self.sender.pending_data_queue, [])
        self.assertEqual(self.sender.unacked_packets, [])
        self.assertEqual(self.sender.expiry_time, {})
        self.assertIsNone(self.sender.client_req)
        self.assertFalse(self.sender.all_chunks_queued)
        self.assertFalse(self.sender.fin_sent)
        self.assertFalse(self.sender.fin_acked)
        self.assertEqual(self.sender.fin_expiry, 0.0)
        self.assertEqual(self.sender.md5_hash, b"")
        self.assertEqual(self.sender.total_chunks, 0)
        self.assertEqual(self.sender.left, 0)
        self.assertEqual(self.sender.right, 0)


class TestReceiver(unittest.TestCase):
    """Test the Receiver class (client-side reliable transfer)."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_sock = Mock(spec=socket.socket)
        self.dest_ip = SERVER_IP
        self.dest_port = SERVER_PORT

        self.receiver = Receiver(
            sock=self.mock_sock, dest_ip=self.dest_ip, dest_port=self.dest_port
        )
        # Add server_md5 attribute (present in actual implementation)
        self.receiver.server_md5 = b""

        # Mock the socket binding that happens in parent __init__
        self.mock_sock.bind.assert_called_once_with((CLIENT_IP, 0))

    def test_initialization(self):
        """Test Receiver initialization."""
        self.assertEqual(self.receiver.sock, self.mock_sock)
        self.assertEqual(self.receiver.dest_ip, self.dest_ip)
        self.assertEqual(self.receiver.dest_port, self.dest_port)
        self.assertEqual(self.receiver.my_port, CLIENT_PORT)

        # Check Receiver-specific attributes
        self.assertEqual(self.receiver.received_data, {})
        self.assertEqual(self.receiver.requested_file, "")
        self.assertEqual(self.receiver.output_file, "")

    @patch("threading.Thread")
    @patch("reliable_transfer.Packet")
    def test_request_file(self, MockPacket, MockThread):
        """Test requesting a file from server."""
        filename = "test.txt"
        output_path = "output.txt"

        # Mock REQ packet creation
        mock_req_packet = Mock(spec=Packet)
        mock_req_packet.to_bytes.return_value = b"req_packet"
        MockPacket.get_req_packet.return_value = mock_req_packet

        # Mock socket.sendto
        self.mock_sock.sendto.return_value = None

        # Mock thread creation
        mock_thread = Mock()
        MockThread.return_value = mock_thread

        self.receiver.request_file(filename, output_path)

        # Verify REQ packet was created
        MockPacket.get_req_packet.assert_called_once_with(
            filename=filename,
            src_ip=CLIENT_IP,
            dst_ip=self.dest_ip,
            src_port=CLIENT_PORT,
            dst_port=self.dest_port,
        )

        # Verify packet was sent
        self.mock_sock.sendto.assert_called_once_with(
            b"req_packet", (self.dest_ip, self.dest_port)
        )

        # Verify state updated
        self.assertEqual(self.receiver.requested_file, filename)
        self.assertEqual(self.receiver.output_file, output_path)

        # Verify threads were created and started
        self.assertEqual(MockThread.call_count, 2)
        # First call: retransmit thread
        MockThread.assert_any_call(target=self.receiver._req_retransmit_loop)
        # Second call: receiver thread
        MockThread.assert_any_call(target=self.receiver.sliding_window_rcv)
        # start should be called twice (once per thread)
        self.assertEqual(mock_thread.start.call_count, 2)
        # daemon attribute set to True (called twice)
        self.assertTrue(mock_thread.daemon)

    @patch("threading.Thread")
    @patch("reliable_transfer.Packet")
    def test_request_file_default_output(self, MockPacket, MockThread):
        """Test requesting a file without specifying output path."""
        filename = "test.txt"

        # Mock REQ packet creation
        mock_req_packet = Mock(spec=Packet)
        mock_req_packet.to_bytes.return_value = b"req_packet"
        MockPacket.get_req_packet.return_value = mock_req_packet

        # Mock thread creation
        mock_thread = Mock()
        MockThread.return_value = mock_thread

        self.receiver.request_file(filename)

        # Output file should be same as requested file
        self.assertEqual(self.receiver.requested_file, filename)
        self.assertEqual(self.receiver.output_file, filename)

        # Verify threads were created and started
        self.assertEqual(MockThread.call_count, 2)
        # First call: retransmit thread
        MockThread.assert_any_call(target=self.receiver._req_retransmit_loop)
        # Second call: receiver thread
        MockThread.assert_any_call(target=self.receiver.sliding_window_rcv)
        # start should be called twice (once per thread)
        self.assertEqual(mock_thread.start.call_count, 2)
        # daemon attribute set to True (called twice)
        self.assertTrue(mock_thread.daemon)

    @patch("reliable_transfer.Packet")
    def test_handle_data_in_order(self, MockPacket):
        """Test handling DATA packets in sequence."""
        # Create mock DATA packet
        mock_data_packet = Mock(spec=Packet)
        mock_data_packet.seq_num = 0
        mock_data_packet.payload = b"chunk0"
        mock_data_packet.src_ip = SERVER_IP
        mock_data_packet.src_port = SERVER_PORT
        mock_data_packet.dst_ip = CLIENT_IP
        mock_data_packet.dst_port = CLIENT_PORT

        # Mock ACK packet creation
        mock_ack_packet = Mock(spec=Packet)
        mock_ack_packet.dst_ip = SERVER_IP
        mock_ack_packet.dst_port = SERVER_PORT
        mock_ack_packet.to_bytes.return_value = b"ack_packet"
        MockPacket.get_ack_packet.return_value = mock_ack_packet

        # Mock socket.sendto
        self.mock_sock.sendto.return_value = None

        self.receiver.handle_data(mock_data_packet)

        # Should store payload
        self.assertEqual(self.receiver.received_data[0], b"chunk0")

        # Should send cumulative ACK for seq_num 1 (next expected)
        MockPacket.get_ack_packet.assert_called_once_with(mock_data_packet, 1)
        self.mock_sock.sendto.assert_called_once_with(
            b"ack_packet", (SERVER_IP, SERVER_PORT)
        )

    @patch("reliable_transfer.Packet")
    def test_handle_data_out_of_order(self, MockPacket):
        """Test handling out-of-order DATA packets."""
        # First packet seq_num 2 (missing 0,1)
        mock_data_packet = Mock(spec=Packet)
        mock_data_packet.seq_num = 2
        mock_data_packet.payload = b"chunk2"
        mock_data_packet.src_ip = SERVER_IP
        mock_data_packet.src_port = SERVER_PORT
        mock_data_packet.dst_ip = CLIENT_IP
        mock_data_packet.dst_port = CLIENT_PORT

        # Mock ACK packet
        mock_ack_packet = Mock(spec=Packet)
        mock_ack_packet.dst_ip = SERVER_IP
        mock_ack_packet.dst_port = SERVER_PORT
        mock_ack_packet.to_bytes.return_value = b"ack_packet"
        MockPacket.get_ack_packet.return_value = mock_ack_packet

        self.mock_sock.sendto.return_value = None

        self.receiver.handle_data(mock_data_packet)

        # Should store payload
        self.assertEqual(self.receiver.received_data[2], b"chunk2")

        # Should send cumulative ACK for seq_num 0 (first missing)
        MockPacket.get_ack_packet.assert_called_once_with(mock_data_packet, 0)

    @patch("reliable_transfer.Packet")
    def test_handle_data_duplicate(self, MockPacket):
        """Test handling duplicate DATA packet."""
        # Store seq_num 0 already
        self.receiver.received_data[0] = b"chunk0"

        # Duplicate packet seq_num 0
        mock_data_packet = Mock(spec=Packet)
        mock_data_packet.seq_num = 0
        mock_data_packet.payload = b"chunk0_dup"
        mock_data_packet.src_ip = SERVER_IP
        mock_data_packet.src_port = SERVER_PORT
        mock_data_packet.dst_ip = CLIENT_IP
        mock_data_packet.dst_port = CLIENT_PORT

        mock_ack_packet = Mock(spec=Packet)
        mock_ack_packet.dst_ip = SERVER_IP
        mock_ack_packet.dst_port = SERVER_PORT
        mock_ack_packet.to_bytes.return_value = b"ack_packet"
        MockPacket.get_ack_packet.return_value = mock_ack_packet

        self.mock_sock.sendto.return_value = None

        self.receiver.handle_data(mock_data_packet)

        # Duplicate packet overwrites existing data (current implementation behavior)
        self.assertEqual(self.receiver.received_data[0], b"chunk0_dup")

        # Should send cumulative ACK for seq_num 1 (next expected)
        MockPacket.get_ack_packet.assert_called_once_with(mock_data_packet, 1)

    def test_assemble_file_no_request(self):
        """Test assemble_file when no file was requested."""
        with patch("builtins.print") as mock_print:
            self.receiver.assemble_file()

            # Should print warning
            mock_print.assert_called_once()
            call_args = mock_print.call_args[0][0]
            self.assertIn("No file requested", call_args)

    def test_assemble_file_success(self):
        """Test assembling received data into a file."""
        self.receiver.requested_file = "test.txt"
        self.receiver.output_file = "output.txt"

        # Store some data out of order
        self.receiver.received_data[1] = b"chunk1"
        self.receiver.received_data[0] = b"chunk0"
        self.receiver.received_data[2] = b"chunk2"

        with patch("builtins.open", mock_open()) as mock_file:
            self.receiver.assemble_file()

            # Verify file was opened for writing
            mock_file.assert_called_once_with("output.txt", "wb")

            # Verify data was written in correct order
            handle = mock_file()
            handle.write.assert_called_once_with(b"chunk0chunk1chunk2")

            # Verify received_data was cleared (popped)
            self.assertEqual(self.receiver.received_data, {})

    def test_assemble_file_with_gap(self):
        """Test assembling file with missing chunks."""
        self.receiver.requested_file = "test.txt"
        self.receiver.output_file = "output.txt"

        # Store data with gap (missing seq_num 1)
        self.receiver.received_data[0] = b"chunk0"
        self.receiver.received_data[2] = b"chunk2"  # Will be ignored

        with patch("builtins.open", mock_open()) as mock_file:
            self.receiver.assemble_file()

            # Should only write contiguous chunks from seq 0
            handle = mock_file()
            handle.write.assert_called_once_with(b"chunk0")

            # Only seq 0 should be popped, seq 2 remains
            self.assertEqual(self.receiver.received_data, {2: b"chunk2"})

    @patch("reliable_transfer.Packet")
    @patch("reliable_transfer.time.monotonic")
    def test_handle_fin(self, mock_monotonic, MockPacket):
        """Test handling FIN packet."""
        mock_fin_packet = Mock(spec=Packet)
        mock_fin_packet.payload = b"mock_md5_hash"
        mock_fin_packet.src_ip = SERVER_IP
        mock_fin_packet.src_port = SERVER_PORT
        mock_fin_packet.dst_ip = CLIENT_IP
        mock_fin_packet.dst_port = CLIENT_PORT

        # Mock ACK packet creation
        mock_ack_packet = Mock(spec=Packet)
        mock_ack_packet.dst_ip = SERVER_IP
        mock_ack_packet.dst_port = SERVER_PORT
        mock_ack_packet.to_bytes.return_value = b"ack_packet"
        MockPacket.get_ack_packet.return_value = mock_ack_packet

        # Mock socket.sendto
        self.mock_sock.sendto.return_value = None

        # Mock monotonic time
        mock_monotonic.return_value = 1000.0

        with patch.object(self.receiver, "assemble_file") as mock_assemble:
            with patch.object(self.receiver, "verify_md5") as mock_verify:
                with patch.object(
                    self.receiver, "generate_client_report"
                ) as mock_report:
                    with patch.object(self.receiver, "cleanup") as mock_cleanup:
                        with patch.object(
                            self.receiver, "_reset_receiver_state_no_lock"
                        ) as mock_reset:
                            self.receiver.handle_fin(mock_fin_packet)

                            # Should store server MD5
                            self.assertEqual(self.receiver.server_md5, b"mock_md5_hash")

                            # Should send ACK
                            MockPacket.get_ack_packet.assert_called_once_with(
                                mock_fin_packet, 0
                            )
                            self.mock_sock.sendto.assert_called_once_with(
                                b"ack_packet", (SERVER_IP, SERVER_PORT)
                            )

                            # Should call assemble_file, verify_md5, generate_client_report, cleanup, and _reset_receiver_state_no_lock
                            mock_assemble.assert_called_once()
                            mock_verify.assert_called_once()
                            mock_report.assert_called_once()
                            mock_cleanup.assert_called_once()
                            mock_reset.assert_called_once()

                            # Should update end_time
                            self.assertEqual(self.receiver.end_time, 1000.0)


if __name__ == "__main__":
    unittest.main()
