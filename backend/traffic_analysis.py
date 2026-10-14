from collections import Counter
from datetime import datetime

from scapy.all import IP, TCP, UDP, ICMP


def packet_to_dict(packet):
    # Extract information from one network packet.
    if IP not in packet:
        return None

    # Identify the transport protocol.
    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        tcp_flags = str(packet[TCP].flags)

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        tcp_flags = None

    elif ICMP in packet:
        protocol = "ICMP"
        source_port = None
        destination_port = None
        tcp_flags = None

    else:
        protocol = "Other"
        source_port = None
        destination_port = None
        tcp_flags = None

    # Store all packet information in a dictionary.
    return {
        "timestamp": datetime.fromtimestamp(
            float(packet.time)
        ).isoformat(timespec="milliseconds"),
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_flags": tcp_flags,
        "size": len(packet),
    }


def calculate_statistics(packet_records):
    # Count protocols and source IP addresses.
    protocol_counts = Counter()
    source_ip_counts = Counter()

    # Track unique addresses.
    unique_source_ips = set()
    unique_destination_ips = set()

    total_bytes = 0

    for packet in packet_records:
        total_bytes += packet["size"]

        protocol_counts[packet["protocol"]] += 1
        source_ip_counts[packet["source_ip"]] += 1

        unique_source_ips.add(packet["source_ip"])
        unique_destination_ips.add(packet["destination_ip"])

    # Return statistics in a structured format.
    return {
        "total_packets": len(packet_records),
        "total_bytes": total_bytes,
        "protocol_counts": dict(protocol_counts),
        "unique_source_ips": len(unique_source_ips),
        "unique_destination_ips": len(unique_destination_ips),
        "top_source_ips": source_ip_counts.most_common(5),
    }
