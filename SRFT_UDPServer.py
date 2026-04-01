#!/usr/bin/env python3
"""
SRFT_UDPServer.py — Secure Reliable File Transfer Server (Phase 2)

Usage (requires root for SOCK_RAW):
    sudo python3 SRFT_UDPServer.py
    sudo python3 SRFT_UDPServer.py --psk /path/to/psk.key
"""

import sys
import socket
import argparse
import time

from config import SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT
from security import load_psk
from secure_transfer import SecureSender


def main():
    parser = argparse.ArgumentParser(description="SRFT Secure UDP Server")
    parser.add_argument(
        "--psk", default="psk.key", help="Path to pre-shared key file (default: psk.key)"
    )
    parser.add_argument("--ip", default=SERVER_IP, help="Server bind IP")
    parser.add_argument("--port", type=int, default=SERVER_PORT, help="Server port")
    args = parser.parse_args()

    # Load PSK
    try:
        psk = load_psk(args.psk)
        print(f"[SERVER] PSK loaded from {args.psk}")
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
        print("[ERROR] Raw sockets require root. Run with: sudo python3 SRFT_UDPServer.py")
        sys.exit(1)

    # Create secure sender and start
    sender = SecureSender(sock, CLIENT_IP, CLIENT_PORT, psk)
    sender.listen_and_serve()

    print(f"[SERVER] Listening on {args.ip}:{args.port}")
    print("[SERVER] Waiting for ClientHello handshake...")
    print("[SERVER] Press Ctrl+C to stop\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
        sender.running = False
        sock.close()


if __name__ == "__main__":
    main()