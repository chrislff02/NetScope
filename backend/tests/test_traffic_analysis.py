
from pathlib import Path
import sys

from scapy.all import IP, TCP, UDP, ICMP

# Allow tests to import our backend modules.
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from traffic_analysis import packet_to_dict, calculate_statistics


def test_tcp_packet_conversion():
    # Create a synthetic TCP packet.
    packet = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / TCP(sport=50000, dport=443, flags="S")
    )

    # Convert the packet into a dictionary.
    result = packet_to_dict(packet)

    # Verify the extracted fields.
    assert result["source_ip"] == "192.168.1.10"
    assert result["destination_ip"] == "8.8.8.8"
    assert result["protocol"] == "TCP"
    assert result["source_port"] == 50000
    assert result["destination_port"] == 443
    assert result["tcp_flags"] == "S"


def test_udp_packet_conversion():
    packet = (
        IP(src="192.168.1.10", dst="1.1.1.1")
        / UDP(sport=53000, dport=53)
    )

    result = packet_to_dict(packet)

    assert result["protocol"] == "UDP"
    assert result["source_port"] == 53000
    assert result["destination_port"] == 53
    assert result["tcp_flags"] is None


def test_icmp_packet_conversion():
    packet = (
        IP(src="192.168.1.10", dst="1.1.1.1")
        / ICMP()
    )

    result = packet_to_dict(packet)

    assert result["protocol"] == "ICMP"
    assert result["source_port"] is None
    assert result["destination_port"] is None


def test_traffic_statistics():
    # Simulate three structured packet records.
    packet_records = [
        {
            "timestamp": "2026-10-15T12:00:00.100",
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "protocol": "TCP",
            "source_port": 50000,
            "destination_port": 443,
            "tcp_flags": "S",
            "size": 100,
        },
        {
            "timestamp": "2026-10-15T12:00:00.500",
            "source_ip": "192.168.1.10",
            "destination_ip": "1.1.1.1",
            "protocol": "UDP",
            "source_port": 53000,
            "destination_port": 53,
            "tcp_flags": None,
            "size": 200,
        },
        {
            "timestamp": "2026-10-15T12:00:01.200",
            "source_ip": "192.168.1.20",
            "destination_ip": "8.8.8.8",
            "protocol": "TCP",
            "source_port": 51000,
            "destination_port": 443,
            "tcp_flags": "A",
            "size": 150,
        },
    ]

    statistics = calculate_statistics(packet_records)

    # Check overall counts.
    assert statistics["total_packets"] == 3
    assert statistics["total_bytes"] == 450

    # Check protocol distribution.
    assert statistics["protocol_counts"] == {
        "TCP": 2,
        "UDP": 1,
    }

    # Check bytes by protocol.
    assert statistics["protocol_bytes"] == {
        "TCP": 250,
        "UDP": 200,
    }

    # Check unique IP addresses.
    assert statistics["unique_source_ips"] == 2
    assert statistics["unique_destination_ips"] == 2

    # Check destination port counts.
    assert statistics["top_destination_ports"] == [
        (443, 2),
        (53, 1),
    ]

    # Check per-second traffic aggregation.
    assert statistics["traffic_over_time"] == {
        "2026-10-15T12:00:00": {
            "packets": 2,
            "bytes": 300,
        },
        "2026-10-15T12:00:01": {
            "packets": 1,
            "bytes": 150,
        },
    }


def test_empty_statistics():
    # The analyzer should handle an empty capture.
    statistics = calculate_statistics([])

    assert statistics["total_packets"] == 0
    assert statistics["total_bytes"] == 0
    assert statistics["protocol_counts"] == {}
    assert statistics["traffic_over_time"] == {}
