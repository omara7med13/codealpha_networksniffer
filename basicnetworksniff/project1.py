from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import argparse


def packet_handler(packet):
    """
    Process each captured packet and display relevant information
    """
    print("\n" + "=" * 50)

    # Display basic packet information
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"IP Packet: {ip_src} -> {ip_dst}")
        print(f"Protocol: {packet[IP].proto}")
        print(f"TTL: {packet[IP].ttl}")

    # Transport layer protocols
    if packet.haslayer(TCP):
        print("TCP Segment:")
        print(f"  Source Port: {packet[TCP].sport}")
        print(f"  Destination Port: {packet[TCP].dport}")
        print(f"  Sequence: {packet[TCP].seq}")
        print(f"  Flags: {packet[TCP].flags}")

    elif packet.haslayer(UDP):
        print("UDP Datagram:")
        print(f"  Source Port: {packet[UDP].sport}")
        print(f"  Destination Port: {packet[UDP].dport}")
        print(f"  Length: {packet[UDP].len}")

    # Payload information
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        print("Payload:")
        try:
            # Try to decode as UTF-8 text
            decoded = payload.decode('utf-8', errors='replace')
            print(f"  {decoded[:200]}")  # Print first 200 chars
        except:
            print("  Binary data (hex):")
            print(f"  {payload[:50].hex()}...")  # Print first 50 bytes as hex

    print("=" * 50 + "\n")


def start_sniffing(interface=None, count=0, filter_exp=None):
    """
    Start packet sniffing on the specified interface
    """
    print(f"Starting packet sniffer on interface {interface or 'default'}")
    print(f"Filter: {filter_exp or 'None'}")
    print("Press Ctrl+C to stop...\n")

    try:
        sniff(
            iface=interface,
            prn=packet_handler,
            count=count,
            filter=filter_exp,
            store=0
        )
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic Network Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 for unlimited)")
    parser.add_argument("-f", "--filter", help="BPF filter expression")

    args = parser.parse_args()

    start_sniffing(
        interface=args.interface,
        count=args.count,
        filter_exp=args.filter
    )