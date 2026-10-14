
from pathlib import Path
from datetime import datetime
import random

from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap


# Find the root directory of our NetScope project.
BASE_DIR = Path(__file__).resolve().parent.parent

# File where our generated packets will be saved.
OUTPUT_FILE = BASE_DIR / "samples" / "sample_traffic.pcap"

# Number of packets to generate.
NUM_PACKETS = 200


def create_sample_traffic():
    # Use a seed so our random traffic is reproducible.
    random.seed(42)

    packets = []

    # Simulated devices on our local network.
    local_ips = [
        "192.168.1.10",
        "192.168.1.20",
        "192.168.1.30",
    ]

    # Simulated remote destinations.
    remote_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.215.14",
        "203.0.113.10",
    ]

    # Common destination ports used by network services.
    ports = [53, 80, 443, 8080]

    # Use the current time as the beginning of our capture.
    start_time = datetime.now().timestamp()

    for i in range(NUM_PACKETS):

        # Randomly choose source and destination addresses.
        source_ip = random.choice(local_ips)
        destination_ip = random.choice(remote_ips)

        # Randomly choose a protocol.
        protocol = random.choices(
            ["TCP", "UDP", "ICMP"],
            weights=[60, 30, 10],
            k=1
        )[0]

        # Create the IP layer.
        packet = IP(src=source_ip, dst=destination_ip)

        if protocol == "TCP":
            # Generate a TCP packet.
            packet /= TCP(
                sport=random.randint(1024, 65535),
                dport=random.choice(ports),
                flags=random.choice(["S", "A", "PA"])
            )

        elif protocol == "UDP":
            # Generate a UDP packet.
            packet /= UDP(
                sport=random.randint(1024, 65535),
                dport=random.choice(ports)
            )

        else:
            # Generate an ICMP echo request.
            packet /= ICMP(type=8)

        # Add a random amount of synthetic payload data.
        payload_size = random.randint(0, 500)
        packet /= Raw(load=b"X" * payload_size)

        # Spread packets across a 60-second capture window.
        packet.time = start_time + (i * 0.3)

        # Store the generated packet.
        packets.append(packet)

    # Ensure the samples folder exists.
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Save all packets to our PCAP file.
    wrpcap(str(OUTPUT_FILE), packets)

    print("\n===== NetScope Sample Traffic Generator =====")
    print(f"Created {len(packets)} sample packets.")
    print(f"Saved to: {OUTPUT_FILE}")
    print("Capture Duration: Approximately 60 seconds")


if __name__ == "__main__":
    create_sample_traffic()
