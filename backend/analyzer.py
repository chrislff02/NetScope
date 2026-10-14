from datetime import datetime
from pathlib import Path
from collections import Counter

from scapy.all import IP, TCP, UDP, ICMP, rdpcap


# Locate the root directory of our NetScope project.
BASE_DIR = Path(__file__).resolve().parent.parent

# Location of our sample PCAP file.
PCAP_FILE = BASE_DIR / "samples" / "sample_traffic.pcap"


def analyze_packets():
    # Make sure our PCAP file exists before reading it.
    if not PCAP_FILE.exists():
        print("Sample PCAP file not found.")
        print("Run capture.py first.")
        return

    # Load packets from the PCAP file.
    packets = rdpcap(str(PCAP_FILE))

    # Keep track of the total number of bytes.
    total_bytes = 0

    # Count how many packets use each protocol.
    protocol_counts = Counter()

    # Count packets sent by each source IP address.
    source_ip_counts = Counter()

    # Store unique source and destination IP addresses.
    unique_source_ips = set()
    unique_destination_ips = set()

    print("\n===== NetScope Packet Analyzer =====")
    print(f"Total Packets: {len(packets)}\n")

    # Loop through every packet in our PCAP file.
    for i, packet in enumerate(packets, start=1):

        # Count the total size of all captured packets.
        packet_size = len(packet)
        total_bytes += packet_size

        # Convert the packet's capture timestamp into local time.
        timestamp = datetime.fromtimestamp(
            float(packet.time)
        ).strftime("%Y-%m-%d %H:%M:%S")

        # Only analyze packets containing an IPv4 layer.
        if IP not in packet:
            protocol_counts["Other"] += 1
            continue

        # Extract source and destination IP addresses.
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        # Determine the packet's protocol and extract port information.
        source_port = None
        destination_port = None
        tcp_flags = None

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        else:
            protocol = "Other"

        # Increase the count for this protocol.
        protocol_counts[protocol] += 1

        # Track how often each source IP appears.
        source_ip_counts[source_ip] += 1

        # Add IP addresses to our sets.
        # Sets automatically prevent duplicates.
        unique_source_ips.add(source_ip)
        unique_destination_ips.add(destination_ip)


        # Display detailed packet information.
        print(f"Packet {i}")
        print(f"Timestamp:      {timestamp}")
        print(f"Source IP:      {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Protocol:       {protocol}")

        # TCP and UDP packets contain port numbers.
        if source_port is not None:
            print(f"Source Port:    {source_port}")
            print(f"Destination Port: {destination_port}")

        # TCP packets also contain flags.
        if tcp_flags is not None:
            print(f"TCP Flags:      {tcp_flags}")

        print(f"Packet Size:    {packet_size} bytes")
        print("-" * 40)


    # Display our final network traffic statistics.
    print("\n===== NetScope Traffic Summary =====")

    print(f"Total Packets: {len(packets)}")
    print(f"Total Bytes: {total_bytes}")

    print("\nProtocol Distribution:")
    for protocol, count in sorted(protocol_counts.items()):
        print(f"{protocol}: {count}")

    print(f"\nUnique Source IPs: {len(unique_source_ips)}")
    print(f"Unique Destination IPs: {len(unique_destination_ips)}")

    print("\nTop Source IP Addresses:")

    for ip, count in source_ip_counts.most_common(5):
        print(f"{ip}: {count} packets")


if __name__ == "__main__":
    analyze_packets()
