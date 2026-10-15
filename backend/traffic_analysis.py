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
    # Count packets by protocol and source IP.
    protocol_counts = Counter()
    source_ip_counts = Counter()

    # Track the total bytes for each protocol.
    protocol_bytes = Counter()

    # Track frequently used destination ports.
    destination_port_counts = Counter()

    # Group traffic into one-second intervals.
    traffic_over_time = {}

    # Track unique source and destination IP addresses.
    unique_source_ips = set()
    unique_destination_ips = set()

    # Track the total bytes across all packets.
    total_bytes = 0

    # Process every packet record.
    for packet in packet_records:
        protocol = packet["protocol"]
        source_ip = packet["source_ip"]
        destination_ip = packet["destination_ip"]
        packet_size = packet["size"]
        destination_port = packet["destination_port"]

        # Update general traffic statistics.
        total_bytes += packet_size
        protocol_counts[protocol] += 1
        protocol_bytes[protocol] += packet_size
        source_ip_counts[source_ip] += 1

        # Store unique IP addresses.
        unique_source_ips.add(source_ip)
        unique_destination_ips.add(destination_ip)

        # Count destination ports for TCP and UDP packets.
        if destination_port is not None:
            destination_port_counts[destination_port] += 1

        # Group packets by their timestamp (one-second intervals).
        second = packet["timestamp"][:19]

        # Create an entry if this second hasn't been seen.
        if second not in traffic_over_time:
            traffic_over_time[second] = {
                "packets": 0,
                "bytes": 0,
            }

        # Update packets and bytes for this second.
        traffic_over_time[second]["packets"] += 1
        traffic_over_time[second]["bytes"] += packet_size

    # Return all calculated statistics.
    return {
        "total_packets": len(packet_records),
        "total_bytes": total_bytes,
        "protocol_counts": dict(protocol_counts),
        "protocol_bytes": dict(protocol_bytes),
        "unique_source_ips": len(unique_source_ips),
        "unique_destination_ips": len(unique_destination_ips),
        "top_source_ips": source_ip_counts.most_common(5),
        "top_destination_ports": destination_port_counts.most_common(5),
        "traffic_over_time": dict(
            sorted(traffic_over_time.items())
        ),
    }
