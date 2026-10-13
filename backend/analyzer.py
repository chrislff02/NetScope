
from pathlib import Path
from scapy.all import IP, TCP, UDP, ICMP, rdpcap

# Find the project directory.
BASE_DIR = Path(__file__).resolve().parent.parent

# Locate our sample traffic file.
PCAP_FILE = BASE_DIR / "samples" / "sample_traffic.pcap"


def analyze_packets():
    # Make sure the PCAP file exists.
    if not PCAP_FILE.exists():
        print("Sample PCAP file not found.")
        print("Run capture.py first.")
        return

    # Read packets from our PCAP file.
    packets = rdpcap(str(PCAP_FILE))

    print("\n===== NetScope Packet Analyzer =====")
    print(f"Total Packets: {len(packets)}\n")

    # Loop through every packet.
    for i, packet in enumerate(packets, start=1):

        # Skip packets that do not contain an IPv4 layer.
        if IP not in packet:
            continue

        # Extract IP addresses.
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        # Identify the protocol.
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other IP"

        # Get packet length in bytes.
        packet_size = len(packet)

        # Display packet information.
        print(f"Packet {i}")
        print(f"Source IP:      {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Protocol:       {protocol}")
        print(f"Packet Size:    {packet_size} bytes")
        print("-" * 40)


if __name__ == "__main__":
    analyze_packets()
