from pathlib import Path
from scapy.all import rdpcap
from traffic_analysis import packet_to_dict, calculate_statistics

# Locate our sample PCAP file.
BASE_DIR = Path(__file__).resolve().parent.parent
PCAP_FILE = BASE_DIR / "samples" / "sample_traffic.pcap"


def analyze_packets():
    # Check that the PCAP file exists.
    if not PCAP_FILE.exists():
        print("Sample PCAP file not found.")
        print("Run capture.py first.")
        return

    # Load packets from the PCAP file.
    packets = rdpcap(str(PCAP_FILE))

    # Convert Scapy packets into dictionaries.
    packet_records = []

    for packet in packets:
        record = packet_to_dict(packet)

        # Skip packets without an IPv4 layer.
        if record is not None:
            packet_records.append(record)

    # Calculate statistics using our reusable function.
    statistics = calculate_statistics(packet_records)

    print("\n===== NetScope Packet Analyzer =====")
    print(f"Total Packets: {len(packets)}\n")

    # Display individual packet information.
    for i, packet in enumerate(packet_records, start=1):
        print(f"Packet {i}")
        print(f"Timestamp:        {packet['timestamp']}")
        print(f"Source IP:        {packet['source_ip']}")
        print(f"Destination IP:   {packet['destination_ip']}")
        print(f"Protocol:         {packet['protocol']}")

        if packet["source_port"] is not None:
            print(f"Source Port:      {packet['source_port']}")
            print(f"Destination Port: {packet['destination_port']}")

        if packet["tcp_flags"] is not None:
            print(f"TCP Flags:        {packet['tcp_flags']}")

        print(f"Packet Size:      {packet['size']} bytes")
        print("-" * 40)

    # Display the traffic summary.
    print("\n===== NetScope Traffic Summary =====")

    print(f"Total Packets: {statistics['total_packets']}")
    print(f"Total Bytes: {statistics['total_bytes']}")

    print("\nProtocol Distribution:")
    for protocol, count in sorted(
        statistics["protocol_counts"].items()
    ):
        print(f"{protocol}: {count}")

    print(
        f"\nUnique Source IPs: "
        f"{statistics['unique_source_ips']}"
    )

    print(
        f"Unique Destination IPs: "
        f"{statistics['unique_destination_ips']}"
    )

    print("\nTop Source IP Addresses:")

    for ip, count in statistics["top_source_ips"]:
        print(f"{ip}: {count} packets")


if __name__ == "__main__":
    analyze_packets()
