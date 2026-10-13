
from pathlib import Path
from scapy.all import IP, TCP, UDP, ICMP, wrpcap

# Find the root directory of our NetScope project.
BASE_DIR = Path(__file__).resolve().parent.parent

# Where our sample network packets will be saved.
OUTPUT_FILE = BASE_DIR / "samples" / "sample_traffic.pcap"


def create_sample_traffic():
    # Create simulated network packets with different protocols.
    packets = [
        IP(src="192.168.1.10", dst="93.184.215.14")
        / TCP(sport=50000, dport=443),

        IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53),

        IP(src="192.168.1.10", dst="1.1.1.1")
        / ICMP(),

        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=80, dport=51000),
    ]

    # Create the samples directory if it doesn't exist.
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Save the packets to a PCAP file.
    wrpcap(str(OUTPUT_FILE), packets)

    print(f"Created {len(packets)} sample packets.")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    create_sample_traffic()
