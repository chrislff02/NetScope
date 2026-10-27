
import json
import socket
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
SOCKET_PATH = BASE_DIR / "data" / "netscope.sock"


def send_test_packet():
    # Use documentation-only IP addresses.
    packet = {
        "timestamp": "2026-10-26T19:00:00.000",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.10",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 443,
        "tcp_flags": "S",
        "size": 120,
    }

    # Connect to the local receiver.
    with socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    ) as client:
        client.settimeout(5)
        client.connect(str(SOCKET_PATH))

        # Send one JSON record followed by a newline.
        message = json.dumps(packet) + "\n"
        client.sendall(message.encode("utf-8"))

        # Read the acknowledgment.
        response = b""

        while not response.endswith(b"\n"):
            chunk = client.recv(1024)

            if not chunk:
                break

            response += chunk

        print("Receiver response:", response.decode().strip())


if __name__ == "__main__":
    send_test_packet()
