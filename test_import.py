#!/usr/bin/env python3
"""Quick import test for reliable_transfer module."""

import socket
import sys

sys.path.insert(0, ".")

try:
    from reliable_transfer import Sender, Receiver

    print("Imported Sender and Receiver successfully")

    # Create raw socket (requires root)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Try to instantiate Sender
    sender = Sender(sock, "127.0.0.1", 9999)
    print("Sender instantiated")

    # Try to instantiate Receiver
    receiver = Receiver(sock, "127.0.0.1", 9999)
    print("Receiver instantiated")

    # Check methods
    print("Sender methods:", [m for m in dir(sender) if not m.startswith("_")])
    print("Receiver methods:", [m for m in dir(receiver) if not m.startswith("_")])

    sock.close()
    print("Test passed")
except Exception as e:
    print(f"Test failed: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)
