import json
from pathlib import Path
import argparse
import os
import tempfile

from scapy.all import sniff, conf
from scapy.error import Scapy_Exception

from traffic_analysis import (
    packet_to_dict,
    calculate_statistics,
)

# Locate the main NetScope project directory.
BASE_DIR = Path(__file__).resolve().parent.parent

# Store local capture metadata outside of Git.
CAPTURE_OUTPUT = BASE_DIR / "data" / "live_capture.json"


def save_capture_data(capture_data):
    """
    Save completed capture metadata securely.

    When the capture runs with sudo, transfer ownership
    of the output file to the user who started it.
    """

    # Ensure the output directory exists.
    CAPTURE_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    # Identify the original user when running with sudo.
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")

    # Create a temporary file in the same directory.
    # This lets us replace the capture file atomically.
    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=CAPTURE_OUTPUT.parent,
            prefix=".capture-",
            suffix=".tmp",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)

            # Restrict file access to its owner.
            os.fchmod(file.fileno(), 0o600)

            # If running with sudo, assign ownership
            # to the original non-root user.
            if (
                os.geteuid() == 0
                and sudo_uid is not None
                and sudo_gid is not None
            ):
                os.fchown(
                    file.fileno(),
                    int(sudo_uid),
                    int(sudo_gid),
                )

            # Write packet metadata to the temporary file.
            json.dump(capture_data, file, indent=2)

        # Replace the previous capture only after the
        # new JSON file has been written successfully.
        os.replace(temporary_path, CAPTURE_OUTPUT)

        print(f"\nCapture data saved to: {CAPTURE_OUTPUT}")

    finally:
        # Remove the temporary file if something failed.
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

def start_live_capture(interface, max_packets, timeout, protocol):
    # Store structured IPv4 packet data.
    packet_records = []

    # Count all packets observed, including non-IPv4 packets.
    raw_packet_count = 0

    def process_packet(packet):
        nonlocal raw_packet_count

        # Count every captured packet.
        raw_packet_count += 1

        # Convert IPv4 packets into dictionaries.
        record = packet_to_dict(packet)

        # Skip unsupported packet types.
        if record is None:
            return

        packet_records.append(record)

        print(
            f"[{record['timestamp']}] "
            f"{record['source_ip']} -> "
            f"{record['destination_ip']} | "
            f"{record['protocol']} | "
            f"{record['size']} bytes"
        )

    print("\n===== NetScope Live Capture =====")
    print(f"Interface: {interface}")
    print(f"Protocol Filter: {protocol.upper()}")
    print(f"Maximum Packets: {max_packets}")
    print(f"Timeout: {timeout} seconds")
    print("\nListening for network traffic...\n")

    # Berkeley Packet Filter expression.
    # Empty filter means all protocols.
    bpf_filter = None if protocol == "all" else protocol

    try:
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=process_packet,
            store=False,
            count=max_packets,
            timeout=timeout,
        )

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    except (OSError, PermissionError, Scapy_Exception) as error:
        print(f"\nCapture failed: {error}")
        print("Check your interface and capture permissions.")
        return

    
    # Calculate statistics once after the capture finishes.
    statistics = calculate_statistics(packet_records)

    # Combine captured packet metadata with statistics.
    capture_data = {
        "source": "live_capture",
        "interface": str(interface),
        "raw_packets_captured": raw_packet_count,
        "packets": packet_records,
        "statistics": statistics,
    }

    # Save the recording atomically with private permissions.
    save_capture_data(capture_data)
    

    print("\n===== NetScope Live Traffic Summary =====")
    print(f"Raw Packets Captured: {raw_packet_count}")
    print(f"IPv4 Packets Analyzed: {statistics['total_packets']}")
    print(f"Total Bytes Analyzed: {statistics['total_bytes']}")

    print("\nProtocol Distribution:")

    for proto, count in sorted(
        statistics["protocol_counts"].items()
    ):
        print(f"{proto}: {count}")

    print(
        f"\nUnique Source IPs: "
        f"{statistics['unique_source_ips']}"
    )

    print(
        f"Unique Destination IPs: "
        f"{statistics['unique_destination_ips']}"
    )


    # Display the total bytes captured for each protocol.
    print("\nBytes by Protocol:")

    for protocol, byte_count in sorted(
        statistics["protocol_bytes"].items()
    ):
        print(f"{protocol}: {byte_count:,} bytes")

    # Display the most commonly used destination ports.
    print("\nTop Destination Ports:")

    if statistics["top_destination_ports"]:
        for port, count in statistics["top_destination_ports"]:
            print(f"Port {port}: {count} packets")
    else:
        print("No TCP or UDP destination ports found.")

    # Display network activity grouped by second.
    print("\nTraffic Over Time:")

    if statistics["traffic_over_time"]:
        for timestamp, data in statistics["traffic_over_time"].items():
            print(
                f"{timestamp} | "
                f"{data['packets']} packets | "
                f"{data['bytes']:,} bytes"
            )
    else:
        print("No IPv4 traffic recorded.")

if __name__ == "__main__":
    # Define command-line arguments.
    parser = argparse.ArgumentParser(
        description="NetScope Live Network Traffic Analyzer"
    )

    parser.add_argument(
        "--interface",
        type=str,
        default=str(conf.iface),
        help="Network interface to monitor"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Maximum number of packets to capture"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Maximum capture duration in seconds"
    )

    parser.add_argument(
        "--protocol",
        type=str,
        choices=["all", "tcp", "udp", "icmp"],
        default="all",
        help="Filter traffic by protocol"
    )

    args = parser.parse_args()

    if args.count <= 0 or args.timeout <= 0:
        parser.error("--count and --timeout must be positive")

    start_live_capture(
        interface=args.interface,
        max_packets=args.count,
        timeout=args.timeout,
        protocol=args.protocol,
    )
