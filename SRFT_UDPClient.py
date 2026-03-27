import socket
import sys
import time
from config import CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT


def main():
    """
    Client entry point: request a file from server and receive it.
    Usage: python SRFT_UDPClient.py <filename> [output_path]
    """
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <filename> [output_path]")
        sys.exit(1)

    filename = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else filename

    # Create raw socket for UDP with IP header included
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Create Receiver instance (dest_ip/dest_port are server address)

    print(f"[SRFT Client] Requesting file '{filename}' from {SERVER_IP}:{SERVER_PORT}")
    print(f"Output will be saved to: {output_path}")

    # Send request and start receiver thread

    # Keep main thread alive (daemon threads run in background)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SRFT Client] Transfer interrupted")


if __name__ == "__main__":
    main()
