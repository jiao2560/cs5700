import socket
from packet import parse_packet
from config import SERVER_PORT


def main():
    """
    Create a raw socket, receive incoming packets,
    and parse only the packets sent to the server port.
    """
    # Create a raw socket for UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print("Server is listening...")

    while True:
        raw_data, addr = sock.recvfrom(65535)

        parsed = parse_packet(raw_data)

        # Ignore packets that are not sent to our server port
        if parsed["udp"]["dst_port"] != SERVER_PORT:
            continue

        print("\n=== Received Packet ===")
        print("From:", addr)
        print(parsed)


if __name__ == "__main__":
    main()
