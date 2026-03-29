# SRFT Project - Person A Deliverable

## Overview

This part implements the lowest layer of the SRFT project using raw UDP sockets in Python.

## Completed Work

- Built raw IPv4 headers manually
- Built raw UDP headers manually
- Implemented UDP checksum calculation
- Implemented packet construction with:
  - IP header
  - UDP header
  - payload
- Implemented packet parsing for incoming raw packets
- Built a raw UDP client
- Built a raw UDP server
- Verified local packet sending and receiving in WSL/Ubuntu

## Main Files

- `config.py`: shared constants and configuration
- `packet.py`: packet construction and parsing functions
- `test_packet.py`: local test for packet build/parse
- `SRFT_UDPClient.py`: sends raw UDP packets
- `SRFT_UDPServer.py`: receives and parses raw UDP packets

## Core Functions

- `compute_checksum(data)`
- `build_ip_header(src_ip, dst_ip, total_length)`
- `build_udp_header(src_port, dst_port, payload)`
- `build_packet(src_ip, dst_ip, src_port, dst_port, payload)`
- `parse_packet(raw_bytes)`

## Test Result

The client successfully sent a raw UDP packet, and the server successfully received and parsed it.

Example parsed output:

- Source IP: `127.0.0.1`
- Destination IP: `127.0.0.1`
- Source Port: `8888`
- Destination Port: `9999`
- Payload: `b'hello from client'`

---

## Person B - Reliable File Transfer (Phase 1)

### Overview

This part implements reliable file transfer on top of Person A's raw socket foundation using a sliding window protocol with cumulative acknowledgments.

### Completed Work

- Created `reliable_transfer.py` with `Sender` (server) and `Receiver` (client) classes
- Implemented sliding window protocol (window size = 4)
- Added sequence numbers to data packets for ordering and duplicate detection
- Implemented cumulative acknowledgments (ACK = next expected sequence number)
- Added timeout (1.0s) and retransmission for lost packets
- Split files into chunks, send with sequence numbers, reassemble at receiver
- Added multithreading: separate send and receive threads for concurrency
- Implemented MD5 hash verification (server sends hash in FIN, client verifies)
- Generate output report `output.txt` with transfer statistics

### Main Files

- `reliable_transfer.py`: `Sender` and `Receiver` classes for reliable transfer
- `transfer_base.py`: shared base class with receive loop and state management
- `app_packet.py`: application-layer packet format (seq, ack, flags, payload)

### Core Functions

- `Sender.listen_and_serve()`: start server threads to handle file requests
- `Receiver.request_file(filename, output_path)`: client entry point to request a file
- `Packet.get_req_packet()`, `get_data_packet()`, `get_ack_packet()`, `get_fin_packet()`: create application packets
- `ReliableTransferBase.sliding_window_rcv()`: base receive loop that dispatches packets

### Protocol Flags (defined in `config.py`)

- `FLAG_REQ` (3): client requests a file (payload = filename)
- `FLAG_DATA` (0): server sends file chunk
- `FLAG_DATA_LAST` (4): last file chunk
- `FLAG_ACK` (1): client acknowledges received data (cumulative ACK)
- `FLAG_FIN` (2): server signals transfer complete (payload = MD5 hash)

### Usage Example

See `tests/test_integration.py` for complete working examples:

```python
import socket
from reliable_transfer import Sender, Receiver
from config import SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT

# Server (sender)
sender_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
sender_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sender = Sender(sender_sock, CLIENT_IP, CLIENT_PORT)
sender.listen_and_serve()

# Client (receiver)
receiver_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
receiver_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
receiver = Receiver(receiver_sock, SERVER_IP, SERVER_PORT)
receiver.request_file("test.txt", "received.txt")
```

### Test Results

- **Unit tests**: `tests/test_reliable_transfer.py` (22 tests, all passing)
- **Integration tests**: `tests/test_integration.py` (6 tests, all passing with root privileges)
  - Basic file transfer
  - Large file transfer (multiple chunks)
  - Consecutive transfers
  - Empty file handling
  - Error handling (non‑existent files)
  - Failed transfer recovery
