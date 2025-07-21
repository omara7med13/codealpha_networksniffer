# codealpha_networksniffer
🛡️ Basic Network Packet Sniffer
A simple yet effective command-line packet sniffer built with Scapy in Python. This tool allows users to monitor and analyze IP, TCP, and UDP network traffic in real time, with detailed packet-level inspection.

🚀 Features
Capture and analyze live packets on a specified network interface

Supports IP, TCP, and UDP protocol parsing

Displays source/destination IPs, ports, flags, TTL, and payloads

Applies custom BPF filters (e.g. tcp, udp port 53, etc.)

Graceful handling of binary or text payloads

🧠 How It Works
The tool uses scapy's powerful sniff() function to capture packets and display useful details using a packet_handler() function. Users can specify:

Network interface

Number of packets to capture

BPF filter expressions (optional)

📦 Requirements
Python 3.x

Scapy
