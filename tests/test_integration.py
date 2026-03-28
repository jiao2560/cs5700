#!/usr/bin/env python3
"""
Integration tests for reliable file transfer (requires root for raw sockets).
"""

import os
import sys
import socket
import threading
import time
import tempfile
import shutil
import unittest
from unittest.mock import patch

# Import the modules to test
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from reliable_transfer import Sender, Receiver
from config import SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT


def is_root():
    """Check if running as root (required for raw sockets)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows - assume not root (raw sockets require admin)
        return False


# Decorator to skip tests if not root
skip_if_not_root = unittest.skipUnless(is_root(), "Requires root for raw sockets")


class TestIntegration(unittest.TestCase):
    """Integration tests for Sender and Receiver."""

    def setUp(self):
        """Set up test fixtures."""
        # Create separate raw sockets for sender and receiver
        self.sender_sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP
        )
        self.sender_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        self.receiver_sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP
        )
        self.receiver_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Instantiate sender and receiver with separate sockets
        # Sender binds to SERVER_IP, receiver binds to CLIENT_IP
        # The second bind will fail silently (caught in __init__) if using same IP
        self.sender = Sender(self.sender_sock, CLIENT_IP, CLIENT_PORT)
        self.receiver = Receiver(self.receiver_sock, SERVER_IP, SERVER_PORT)

        # Create temporary directory for test files
        self.temp_dir = tempfile.mkdtemp(prefix="srft_test_")

        # Track threads for cleanup
        self.sender_thread = None
        self.receiver_thread = None

    def tearDown(self):
        """Clean up after each test."""
        # Stop sender and receiver threads
        self.sender.running = False
        self.receiver.running = False

        # Close both sockets
        self.sender_sock.close()
        self.receiver_sock.close()

        # Remove temporary directory
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _start_sender(self):
        """Start sender thread."""
        self.sender_thread = threading.Thread(target=self.sender.listen_and_serve)
        self.sender_thread.daemon = True
        self.sender_thread.start()
        # Small delay for thread startup
        time.sleep(0.1)

    def _start_receiver(self):
        """Start receiver thread (no-op - receiver threads are started by request_file)."""
        pass

    @skip_if_not_root
    def test_file_transfer_success(self):
        """Test successful transfer of an existing file."""
        # Create a test file
        test_content = b"Hello, World! This is a test file for integration testing."
        test_file = os.path.join(self.temp_dir, "test.txt")
        with open(test_file, "wb") as f:
            f.write(test_content)

        # Start sender thread
        self._start_sender()

        # Request file
        output_file = os.path.join(self.temp_dir, "output.txt")
        self.receiver.request_file(test_file, output_file)

        # Wait for transfer to complete (max 10 seconds)
        timeout = time.time() + 10
        while time.time() < timeout:
            if os.path.exists(output_file):
                break
            time.sleep(0.1)

        # Verify file was transferred
        self.assertTrue(os.path.exists(output_file), "Output file not created")

        # Verify content
        with open(output_file, "rb") as f:
            transferred_content = f.read()
        self.assertEqual(transferred_content, test_content, "File content mismatch")

        # Verify MD5 (should have been printed)
        # We could capture stdout, but for now just check file existence

    @skip_if_not_root
    def test_file_nonexistent(self):
        """Test requesting a non-existent file."""
        # Start sender thread
        self._start_sender()

        # Request non-existent file
        nonexistent = os.path.join(self.temp_dir, "nonexistent.txt")
        output_file = os.path.join(self.temp_dir, "output.txt")

        # Capture prints to verify error message
        with patch("builtins.print") as mock_print:
            self.receiver.request_file(nonexistent, output_file)

            # Wait a bit for transfer attempt
            time.sleep(2)

            # Verify error was printed (by sender when reading file)
            # The sender prints error when transfer_file fails
            error_found = False
            for call in mock_print.call_args_list:
                args = call[0]
                if len(args) > 0 and "nonexistent" in str(args[0]).lower():
                    error_found = True
                    break

            self.assertTrue(error_found, "Expected error message for non-existent file")

        # Output file should not exist
        self.assertFalse(
            os.path.exists(output_file),
            "Output file should not exist for non-existent input",
        )

    @skip_if_not_root
    def test_failed_then_successful_transfer(self):
        """Test that after a failed transfer (non-existent file),
        a new receiver can successfully transfer a file."""
        # Start sender thread
        self._start_sender()

        # First, attempt to transfer a non-existent file
        nonexistent = os.path.join(self.temp_dir, "nonexistent.txt")
        output1 = os.path.join(self.temp_dir, "output1.txt")

        with patch("builtins.print"):
            self.receiver.request_file(nonexistent, output1)
            # Wait for retries to complete (max attempts = 3, timeout = 1 sec each)
            time.sleep(4)

        # Explicitly stop the receiver before creating a new one
        self.receiver.running = False
        self.receiver.req_retransmit_active = False
        self.receiver.transfer_complete = True
        # Close socket to unblock receiver threads
        self.receiver_sock.close()
        time.sleep(0.3)  # Allow threads to exit

        # Create a new socket for the new receiver instance
        self.receiver_sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP
        )
        self.receiver_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Create a new receiver instance for the successful transfer
        self.receiver = Receiver(self.receiver_sock, SERVER_IP, SERVER_PORT)

        # Create a real test file
        test_content = b"Successful transfer after failure"
        test_file = os.path.join(self.temp_dir, "real.txt")
        with open(test_file, "wb") as f:
            f.write(test_content)

        output2 = os.path.join(self.temp_dir, "output2.txt")
        self.receiver.request_file(test_file, output2)

        # Wait for transfer to complete
        timeout = time.time() + 10
        while time.time() < timeout and not os.path.exists(output2):
            time.sleep(0.1)

        self.assertTrue(
            os.path.exists(output2), "File should be transferred after failure"
        )
        with open(output2, "rb") as f:
            self.assertEqual(f.read(), test_content)

    @skip_if_not_root
    def test_consecutive_transfers(self):
        """Test multiple file transfers in sequence."""
        # Create two test files
        content1 = b"First file content"
        content2 = b"Second file content"

        file1 = os.path.join(self.temp_dir, "file1.txt")
        file2 = os.path.join(self.temp_dir, "file2.txt")
        output1 = os.path.join(self.temp_dir, "out1.txt")
        output2 = os.path.join(self.temp_dir, "out2.txt")

        with open(file1, "wb") as f:
            f.write(content1)
        with open(file2, "wb") as f:
            f.write(content2)

        # Start sender thread
        self._start_sender()

        # First transfer
        self.receiver.request_file(file1, output1)
        timeout = time.time() + 10
        while time.time() < timeout and not os.path.exists(output1):
            time.sleep(0.1)

        self.assertTrue(os.path.exists(output1), "First file not transferred")
        with open(output1, "rb") as f:
            self.assertEqual(f.read(), content1)

        # Reset receiver state for next transfer
        # Note: receiver.reset_receiver_state() is called automatically after each transfer
        # Wait a bit for cleanup
        time.sleep(0.5)

        # Second transfer
        self.receiver.request_file(file2, output2)
        timeout = time.time() + 10
        while time.time() < timeout and not os.path.exists(output2):
            time.sleep(0.1)

        self.assertTrue(os.path.exists(output2), "Second file not transferred")
        with open(output2, "rb") as f:
            self.assertEqual(f.read(), content2)

    @skip_if_not_root
    def test_empty_file_transfer(self):
        """Test transfer of an empty file."""
        empty_file = os.path.join(self.temp_dir, "empty.txt")
        with open(empty_file, "wb") as f:
            pass  # Empty file

        output_file = os.path.join(self.temp_dir, "empty_out.txt")

        self._start_sender()
        self.receiver.request_file(empty_file, output_file)

        timeout = time.time() + 10
        while time.time() < timeout and not os.path.exists(output_file):
            time.sleep(0.1)

        self.assertTrue(os.path.exists(output_file), "Empty file not transferred")
        with open(output_file, "rb") as f:
            self.assertEqual(len(f.read()), 0, "Empty file should have zero bytes")

    @skip_if_not_root
    def test_large_file_transfer(self):
        """Test transfer of a file larger than one chunk."""
        # Create file larger than MAX_PAYLOAD_SIZE - HEADER_SIZE
        from config import MAX_PAYLOAD_SIZE
        from app_packet import HEADER_SIZE

        chunk_size = MAX_PAYLOAD_SIZE - HEADER_SIZE
        # Create 2.5 chunks
        large_content = b"X" * (chunk_size * 2 + chunk_size // 2)
        large_file = os.path.join(self.temp_dir, "large.txt")
        output_file = os.path.join(self.temp_dir, "large_out.txt")

        with open(large_file, "wb") as f:
            f.write(large_content)

        self._start_sender()
        self.receiver.request_file(large_file, output_file)

        timeout = time.time() + 15  # Longer timeout for large file
        while time.time() < timeout and not os.path.exists(output_file):
            time.sleep(0.1)

        self.assertTrue(os.path.exists(output_file), "Large file not transferred")
        with open(output_file, "rb") as f:
            transferred = f.read()
        self.assertEqual(transferred, large_content, "Large file content mismatch")


if __name__ == "__main__":
    unittest.main()
