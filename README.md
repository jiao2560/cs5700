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
