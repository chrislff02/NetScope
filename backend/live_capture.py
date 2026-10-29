
import argparse
import json
import os
import tempfile

from pathlib import Path

from scapy.all import sniff, conf
from scapy.error import Scapy_Exception

from traffic_analysis import (
    packet_to_dict,
    calculate_statistics,
)

from packet_forwarder import PacketForwarder


# Locate the main NetScope project directory.
BASE_DIR = Path(__file__).resolve().parent.parent

# Store local capture metadata outside of Git.
CAPTURE_OUTPUT = BASE_DIR / "data" / "live_capture.json"


def save_capture_data(capture_data):
    """
    Save completed capture metadata securely.

    When running with sudo, transfer ownership of
    the output file to the original user.
    """

    CAPTURE_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")

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

            # Restrict file access.
            os.fchmod(file.fileno(), 0o600)

            # Restore ownership to the original sudo user.
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

            json.dump(capture_data, file, indent=2)

        # Atomically replace the previous capture.
        os.replace(temporary_path, CAPTURE_OUTPUT)

        print(f"\nCapture data saved to: {CAPTURE_OUTPUT}")

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def start_live_capture(
    interface,
    max_packets,
    timeout,
    protocol,
    stream=False,
):
    """
    Capture and analyze network packets.

    When streaming is enabled, enqueue packet metadata
    for forwarding to NetScope's FastAPI receiver.
    """

    packet_records = []
    raw_packet_count = 0

    # Start a background forwarder only when requested.
    forwarder = PacketForwarder() if stream else None

    if forwarder is not None:
        forwarder.start()

    def process_packet(packet):
        nonlocal raw_packet_count

        # Count every raw packet captured.
        raw_packet_count += 1

        # Convert IPv4 packets to structured metadata.
        record = packet_to_dict(packet)

        if record is None:
            return

        # Preserve packet metadata for statistics and JSON.
        packet_records.append(record)

        # Queue metadata without waiting for the Unix socket.
        if forwarder is not None:
            forwarder.enqueue(record)

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
    print(f"Live Streaming: {'Enabled' if stream else 'Disabled'}")
    print("\nListening for network traffic...\n")

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

    finally:
        # Always attempt to stop the forwarding worker.
        if forwarder is not None:
            finished = forwarder.stop(timeout=5)
            forward_stats = forwarder.get_statistics()

            print("\n===== NetScope Packet Forwarding =====")
            print(f"Queued: {forward_stats['queued']}")
            print(f"Sent: {forward_stats['sent']}")
            print(f"Failed: {forward_stats['failed']}")
            print(f"Dropped: {forward_stats['dropped']}")
            print(f"Pending: {forward_stats['pending']}")

            if not finished:
                print(
                    "Warning: forwarding did not finish "
                    "before the shutdown timeout."
                )

    # Calculate statistics once after capture completes.
    statistics = calculate_statistics(packet_records)

    capture_data = {
        "source": "live_capture",
        "interface": str(interface),
        "raw_packets_captured": raw_packet_count,
        "packets": packet_records,
        "statistics": statistics,
    }

    # Preserve the existing secure completed-capture save.
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

    print("\nBytes by Protocol:")

    for proto, byte_count in sorted(
        statistics["protocol_bytes"].items()
    ):
        print(f"{proto}: {byte_count:,} bytes")

    print("\nTop Destination Ports:")

    if statistics["top_destination_ports"]:
        for port, count in statistics["top_destination_ports"]:
            print(f"Port {port}: {count} packets")
    else:
        print("No TCP or UDP destination ports found.")

    print("\nTraffic Over Time:")

    if statistics["traffic_over_time"]:
        for timestamp, data in (
            statistics["traffic_over_time"].items()
        ):
            print(
                f"{timestamp} | "
                f"{data['packets']} packets | "
                f"{data['bytes']:,} bytes"
            )
    else:
        print("No IPv4 traffic recorded.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NetScope Live Network Traffic Analyzer"
    )

    parser.add_argument(
        "--interface",
        type=str,
        default=str(conf.iface),
        help="Network interface to monitor",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Maximum number of packets to capture",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Maximum capture duration in seconds",
    )

    parser.add_argument(
        "--protocol",
        type=str,
        choices=["all", "tcp", "udp", "icmp"],
        default="all",
        help="Filter traffic by protocol",
    )

    # Enable forwarding into FastAPI's live WebSocket pipeline.
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Forward captured metadata to NetScope Live Mode",
    )

    args = parser.parse_args()

    if args.count <= 0 or args.timeout <= 0:
        parser.error(
            "--count and --timeout must be positive"
        )

    start_live_capture(
        interface=args.interface,
        max_packets=args.count,
        timeout=args.timeout,
        protocol=args.protocol,
        stream=args.stream,
    )
