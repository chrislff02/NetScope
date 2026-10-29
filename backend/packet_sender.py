
import json
import socket

from pathlib import Path


# NetScope's local Unix socket.
BASE_DIR = Path(__file__).resolve().parent.parent
SOCKET_PATH = BASE_DIR / "data" / "netscope.sock"

# Match the receiver's maximum message size.
MAX_MESSAGE_BYTES = 4096

# Limit how long a socket operation may block.
SOCKET_TIMEOUT = 1.0


def send_packet_metadata(packet, socket_path=SOCKET_PATH):
    """
    Send one packet metadata dictionary to NetScope's
    Unix socket receiver.

    Returns True if the receiver accepts the packet.
    Returns False if delivery fails or is rejected.
    """

    try:
        # Serialize packet metadata as newline-delimited JSON.
        message = (
            json.dumps(packet, separators=(",", ":")) + "\n"
        ).encode("utf-8")

        # Reject messages that exceed the receiver's limit.
        if len(message) > MAX_MESSAGE_BYTES:
            return False

        # Connect using a local Unix domain socket.
        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        ) as client:

            client.settimeout(SOCKET_TIMEOUT)
            client.connect(str(socket_path))

            # Send one complete message.
            client.sendall(message)

            # Read the receiver's acknowledgment.
            response = bytearray()

            while not response.endswith(b"\n"):
                chunk = client.recv(256)

                if not chunk:
                    return False

                response.extend(chunk)

                # Avoid accumulating an unlimited response.
                if len(response) > 256:
                    return False

        acknowledgment = json.loads(response)

        return (
            isinstance(acknowledgment, dict)
            and acknowledgment.get("status") == "accepted"
        )

    except (
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
    ):
        # The receiver may be unavailable, or the message
        # may be malformed. Do not crash the capture process.
        return False
