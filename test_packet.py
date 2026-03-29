from packet import build_packet, parse_packet
from config import SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT


def main():
    payload = b"hello SRFT"

    packet = build_packet(
        src_ip=CLIENT_IP,
        dst_ip=SERVER_IP,
        src_port=CLIENT_PORT,
        dst_port=SERVER_PORT,
        payload=payload
    )

    print("Built packet:", packet)
    print("Packet length:", len(packet))

    parsed = parse_packet(packet)
    print("Parsed packet:")
    print(parsed)


if __name__ == "__main__":
    main()