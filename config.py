SERVER_IP = "127.0.0.1"
CLIENT_IP = "127.0.0.1"

SERVER_PORT = 9999
CLIENT_PORT = 8888

MTU = 1500
IP_HEADER_LEN = 20
UDP_HEADER_LEN = 8

MAX_PAYLOAD_SIZE = MTU - IP_HEADER_LEN - UDP_HEADER_LEN

TIMEOUT = 1.0
WINDOW_SIZE = 4

# flags
FLAG_DATA = 0  # A data message from the server
FLAG_ACK = 1  # An ack message from the client
FLAG_FIN = 2  # File transfer complete from server
FLAG_REQ = 3  # Request from client for a given file, payload is file name
FLAG_DATA_LAST = 4  # Last data message from the server (DATA | LAST)
FLAG_CLIENT_HELLO = 5  # Phase 2: handshake initiation from client
FLAG_SERVER_HELLO = 6  # Phase 2: handshake response from server

# Phase 2 security constants
HANDSHAKE_TIMEOUT = 3.0  # Seconds to wait for handshake response
HANDSHAKE_MAX_RETRIES = 5  # Max ClientHello retransmissions
GCM_NONCE_SIZE = 12  # AES-GCM nonce/IV size (bytes)
GCM_TAG_SIZE = 16  # AES-GCM authentication tag size (bytes)
SECURITY_OVERHEAD = GCM_NONCE_SIZE + GCM_TAG_SIZE  # 28 bytes per encrypted packet