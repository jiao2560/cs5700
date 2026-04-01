#!/usr/bin/env python3
"""
SRFT_UDPClient.py — Secure Reliable File Transfer Client (Phase 2)

Usage (requires root for SOCK_RAW):
    sudo python3 SRFT_UDPClient.py <filename> [-o output_path]
    sudo python3 SRFT_UDPClient.py /path/to/test.txt -o received.txt
    sudo python3 SRFT_UDPClient.py /path/to/image.png --psk /path/to/psk.key
"""

import sys
import socket
import argparse
import time
import os

from config import SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT
from security import load_psk
from secure_transfer import SecureReceiver


def main():
    parser = argparse.ArgumentParser(description="SRFT Secure UDP Client")
    parser.add_argument("filename", help="File path to request from server")
    parser.add_argument(
        "-o", "--output", default=None, help="Output file path (default: same as filename basename)"
    )
    parser.add_argument(
        "--psk", default="psk.key", help="Path to pre-shared key file (default: psk.key)"
    )
    parser.add_argument(
        "--timeout", type=int, default=120, help="Max wait time in seconds (default: 120)"
    )
    args = parser.parse_args()

    # Load PSK
    try:
        psk = load_psk(args.psk)
        print(f"[CLIENT] PSK loaded from {args.psk}")
    except FileNotFoundError:
        print(f"[ERROR] PSK file not found: {args.psk}")
        print("  Generate one with:  python3 security.py generate")
        sys.exit(1)
    except ValueError as e:
        print(f"[ERROR] Invalid PSK: {e}")
        sys.exit(1)

    # Create raw socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("[ERROR] Raw sockets require root. Run with: sudo python3 SRFT_UDPClient.py ...")
        sys.exit(1)

    # Determine output path
    output_path = args.output if args.output else os.path.basename(args.filename)

    # Create secure receiver
    receiver = SecureReceiver(sock, SERVER_IP, SERVER_PORT, psk)

    print(f"[CLIENT] Requesting: {args.filename}")
    print(f"[CLIENT] Output:     {output_path}")
    print()

    # Request file (handshake + encrypted transfer)
    receiver.request_file(args.filename, output_path)

    # Wait for transfer completion
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        if receiver.transfer_complete:
            break
        time.sleep(0.1)

    if receiver.transfer_complete:
        print(f"\n[CLIENT] File saved to: {output_path}")
        if os.path.exists(output_path):
            size = os.path.getsize(output_path)
            print(f"[CLIENT] File size: {size} bytes")
    else:
        print(f"\n[CLIENT] Transfer did not complete within {args.timeout}s")
        if receiver.handshake_status == "Fail":
            print("[CLIENT] Handshake failed — check PSK match")

    sock.close()


if __name__ == "__main__":
    main()