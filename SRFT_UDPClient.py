import socket
from packet import build_packet
from config import CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT


def main():
    """
    Create a raw socket, manually build a UDP packet,
    and send it to the server.
    """
    # Create a raw socket for UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    # Tell the OS that the IP header is included in the packet we build
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    payload = b"hello from client"

    packet = build_packet(
        src_ip=CLIENT_IP,
        dst_ip=SERVER_IP,
        src_port=CLIENT_PORT,
        dst_port=SERVER_PORT,
        payload=payload
    )

    sock.sendto(packet, (SERVER_IP, SERVER_PORT))
    print("Packet sent!")


if __name__ == "__main__":
    main()