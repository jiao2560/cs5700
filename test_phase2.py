#!/usr/bin/env python3
"""
test_phase2.py — Phase 2 Security Layer Tests

Run with root:
    sudo python3 test_phase2.py

Tests:
    1. Small text file transfer
    2. Large text file transfer (multiple chunks)
    3. Binary file transfer (.png-like)
    4. Empty file transfer
    5. Wrong PSK → handshake rejection
    6. Consecutive transfers (two files in a row)
"""

import os
import sys
import socket
import threading
import time
import tempfile
import shutil
import hashlib

from config import SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT
from security import load_psk, generate_psk
from secure_transfer import SecureSender, SecureReceiver


# ── Helpers ──────────────────────────────────────────────────────────────

def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def files_match(file_a, file_b):
    """Compare two files by SHA-256."""
    def sha(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    return sha(file_a) == sha(file_b)


def create_test_files(temp_dir):
    """Create various test files and return their paths."""
    files = {}

    # 1. Small text file (120 bytes)
    small_txt = os.path.join(temp_dir, "small.txt")
    with open(small_txt, "w") as f:
        for i in range(10):
            f.write(f"hello world line {i}\n")
    files["small_txt"] = small_txt

    # 2. Large text file (~50KB, multiple chunks)
    large_txt = os.path.join(temp_dir, "large.txt")
    with open(large_txt, "w") as f:
        for i in range(2000):
            f.write(f"Line {i:05d}: This is a test line for large file transfer.\n")
    files["large_txt"] = large_txt

    # 3. Binary file (~10KB, simulating a .png)
    binary_file = os.path.join(temp_dir, "test_image.bin")
    with open(binary_file, "wb") as f:
        # PNG-like header + random binary data
        f.write(b"\x89PNG\r\n\x1a\n")  # PNG signature
        f.write(os.urandom(10000))
    files["binary"] = binary_file

    # 4. Empty file
    empty_file = os.path.join(temp_dir, "empty.txt")
    with open(empty_file, "wb") as f:
        pass
    files["empty"] = empty_file

    # 5. Medium binary file (~100KB)
    medium_bin = os.path.join(temp_dir, "medium.bin")
    with open(medium_bin, "wb") as f:
        f.write(os.urandom(100_000))
    files["medium_bin"] = medium_bin

    # Print file sizes
    print("\n📁 Test files created:")
    for name, path in files.items():
        size = os.path.getsize(path)
        print(f"   {name:15s} → {size:>8,} bytes  ({path})")
    print()

    return files


def make_sockets():
    """Create a pair of raw sockets for sender and receiver."""
    sender_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sender_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    receiver_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    receiver_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    return sender_sock, receiver_sock


def run_transfer(psk_sender, psk_receiver, input_file, output_file, timeout=30):
    """
    Run a complete secure file transfer.
    Returns dict with results.
    """
    sender_sock, receiver_sock = make_sockets()

    sender = SecureSender(sender_sock, CLIENT_IP, CLIENT_PORT, psk_sender)
    receiver = SecureReceiver(receiver_sock, SERVER_IP, SERVER_PORT, psk_receiver)

    # Start sender
    sender.listen_and_serve()
    time.sleep(0.1)

    # Request file
    receiver.request_file(input_file, output_file)

    # Wait for completion
    deadline = time.time() + timeout
    while time.time() < deadline:
        if receiver.transfer_complete:
            break
        time.sleep(0.1)

    # Collect results
    result = {
        "completed": receiver.transfer_complete,
        "handshake_server": sender.handshake_status,
        "handshake_client": receiver.handshake_status,
        "sha256_match": sender.sha256_match,
        "aead_failures_server": (
            sender.security_ctx.aead_failures if sender.security_ctx else 0
        ),
        "aead_failures_client": (
            receiver.security_ctx.aead_failures if receiver.security_ctx else 0
        ),
        "replay_drops_client": (
            receiver.security_ctx.replay_drops if receiver.security_ctx else 0
        ),
        "output_exists": os.path.exists(output_file),
        "files_match": (
            files_match(input_file, output_file)
            if os.path.exists(output_file) and os.path.getsize(input_file) > 0
            else os.path.exists(output_file)
            and os.path.getsize(output_file) == 0
            and os.path.getsize(input_file) == 0
        ),
    }

    # Cleanup
    sender.running = False
    receiver.running = False
    sender_sock.close()
    receiver_sock.close()
    time.sleep(0.3)

    return result


def print_result(test_name, result, expected_pass=True):
    """Pretty-print test result."""
    if expected_pass:
        success = (
            result["completed"]
            and result["handshake_server"] == "Success"
            and result["handshake_client"] == "Success"
            and result["output_exists"]
            and result["files_match"]
        )
    else:
        # For failure tests (wrong PSK)
        success = (
            result["handshake_server"] == "Fail"
            or result["handshake_client"] == "Fail"
        )

    icon = "✅" if success else "❌"
    print(f"\n{'='*60}")
    print(f"{icon}  {test_name}")
    print(f"{'='*60}")
    print(f"   Completed:          {result['completed']}")
    print(f"   Handshake (server): {result['handshake_server']}")
    print(f"   Handshake (client): {result['handshake_client']}")
    print(f"   Output exists:      {result['output_exists']}")
    print(f"   Files match:        {result['files_match']}")
    print(f"   SHA-256 match:      {result['sha256_match']}")
    print(f"   AEAD failures (S):  {result['aead_failures_server']}")
    print(f"   AEAD failures (C):  {result['aead_failures_client']}")
    print(f"   Replay drops (C):   {result['replay_drops_client']}")

    return success


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    if not is_root():
        print("❌ Must run as root: sudo python3 test_phase2.py")
        sys.exit(1)

    print("=" * 60)
    print("  SRFT Phase 2 — Security Layer Tests")
    print("=" * 60)

    # Create temp directory for test files
    temp_dir = tempfile.mkdtemp(prefix="srft_phase2_test_")
    print(f"\n📂 Temp directory: {temp_dir}")

    # Create test files
    files = create_test_files(temp_dir)

    # Load the real PSK
    psk = load_psk("psk.key")

    results = []

    # ── Test 1: Small text file ──────────────────────────────────────
    print("\n🔄 Test 1: Small text file transfer...")
    output = os.path.join(temp_dir, "small_received.txt")
    r = run_transfer(psk, psk, files["small_txt"], output)
    results.append(print_result("Test 1 — Small Text File", r))

    # ── Test 2: Large text file (multiple chunks) ────────────────────
    print("\n🔄 Test 2: Large text file transfer (~50KB, multiple chunks)...")
    output = os.path.join(temp_dir, "large_received.txt")
    r = run_transfer(psk, psk, files["large_txt"], output, timeout=60)
    results.append(print_result("Test 2 — Large Text File (multi-chunk)", r))

    # ── Test 3: Binary file ──────────────────────────────────────────
    print("\n🔄 Test 3: Binary file transfer (~10KB)...")
    output = os.path.join(temp_dir, "binary_received.bin")
    r = run_transfer(psk, psk, files["binary"], output)
    results.append(print_result("Test 3 — Binary File", r))

    # ── Test 4: Empty file ───────────────────────────────────────────
    print("\n🔄 Test 4: Empty file transfer...")
    output = os.path.join(temp_dir, "empty_received.txt")
    r = run_transfer(psk, psk, files["empty"], output)
    results.append(print_result("Test 4 — Empty File", r))

    # ── Test 5: Wrong PSK (handshake should fail) ────────────────────
    print("\n🔄 Test 5: Wrong PSK — handshake should fail...")
    wrong_psk = os.urandom(32)  # Random wrong key
    output = os.path.join(temp_dir, "wrong_psk_output.txt")
    r = run_transfer(psk, wrong_psk, files["small_txt"], output, timeout=20)
    results.append(print_result("Test 5 — Wrong PSK (expect failure)", r, expected_pass=False))

    # ── Test 6: Medium binary file ───────────────────────────────────
    print("\n🔄 Test 6: Medium binary file transfer (~100KB)...")
    output = os.path.join(temp_dir, "medium_received.bin")
    r = run_transfer(psk, psk, files["medium_bin"], output, timeout=60)
    results.append(print_result("Test 6 — Medium Binary File (100KB)", r))

    # ── Summary ──────────────────────────────────────────────────────
    passed = sum(results)
    total = len(results)
    print(f"\n{'='*60}")
    print(f"  RESULTS: {passed}/{total} tests passed")
    print(f"{'='*60}")

    if passed == total:
        print("  🎉 All tests passed! Phase 2 security layer is working.\n")
    else:
        failed_tests = [i + 1 for i, r in enumerate(results) if not r]
        print(f"  ⚠️  Failed tests: {failed_tests}\n")

    # Cleanup
    print(f"📂 Test files in: {temp_dir}")
    print("   (delete manually when done: rm -rf {temp_dir})")


if __name__ == "__main__":
    main()