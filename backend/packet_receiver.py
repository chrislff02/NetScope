
import asyncio
import ipaddress
import json
import os
import stat

from datetime import datetime
from pathlib import Path


# Store the socket inside NetScope's private data directory.
BASE_DIR = Path(__file__).resolve().parent.parent
SOCKET_PATH = BASE_DIR / "data" / "netscope.sock"

# Maximum size of one packet metadata message.
MAX_MESSAGE_BYTES = 4096

# Fields expected from traffic_analysis.packet_to_dict().
PACKET_FIELDS = {
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "tcp_flags",
    "size",
}


def validate_packet(packet):
    """
    Validate incoming network packet metadata.

    The receiver accepts metadata only, never raw payloads.
    """
    if not isinstance(packet, dict):
        raise ValueError("Packet must be a JSON object.")

    if set(packet) != PACKET_FIELDS:
        raise ValueError("Packet fields are invalid.")

    # Validate the packet timestamp.
    timestamp = packet["timestamp"]

    if not isinstance(timestamp, str):
        raise ValueError("Invalid timestamp.")

    try:
        datetime.fromisoformat(timestamp)
    except ValueError as error:
        raise ValueError("Invalid timestamp.") from error

    # Only accept IPv4 addresses in the current version.
    for field in ("source_ip", "destination_ip"):
        address = packet[field]

        if not isinstance(address, str):
            raise ValueError(f"Invalid {field}.")

        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as error:
            raise ValueError(f"Invalid {field}.") from error

        if parsed_address.version != 4:
            raise ValueError("Only IPv4 is supported.")

    # Validate supported protocols.
    protocol = packet["protocol"]

    if protocol not in ("TCP", "UDP", "ICMP", "Other"):
        raise ValueError("Unsupported protocol.")

    # Validate packet size.
    size = packet["size"]

    if type(size) is not int or not 0 < size <= 65535:
        raise ValueError("Invalid packet size.")

    # Validate transport ports.
    for field in ("source_port", "destination_port"):
        port = packet[field]

        if port is not None:
            if type(port) is not int or not 0 <= port <= 65535:
                raise ValueError(f"Invalid {field}.")

    # Validate TCP flags.
    flags = packet["tcp_flags"]

    if flags is not None:
        if (
            not isinstance(flags, str)
            or len(flags) > 16
            or not flags.isascii()
        ):
            raise ValueError("Invalid TCP flags.")

    # Check protocol-specific fields.
    if protocol in ("TCP", "UDP"):
        if (
            packet["source_port"] is None
            or packet["destination_port"] is None
        ):
            raise ValueError("TCP/UDP ports are required.")
    else:
        if (
            packet["source_port"] is not None
            or packet["destination_port"] is not None
        ):
            raise ValueError("Unexpected transport ports.")

    if protocol != "TCP" and flags is not None:
        raise ValueError("TCP flags on non-TCP packet.")

    return packet


async def handle_connection(reader, writer):
    """
    Receive and validate one newline-delimited JSON record.
    """

    try:
        # Read at most one bounded message.
        message = await asyncio.wait_for(
            reader.readline(),
            timeout=5,
        )

        if (
            not message
            or len(message) > MAX_MESSAGE_BYTES
            or not message.endswith(b"\n")
        ):
            raise ValueError("Invalid message length or framing.")

        # Convert JSON into a Python dictionary.
        packet = json.loads(message.decode("utf-8"))

        # Validate the packet's structure and values.
        validate_packet(packet)

        print(
            f"Accepted {packet['protocol']} packet "
            f"({packet['size']} bytes)"
        )

        response = {"status": "accepted"}

    except (
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
        asyncio.TimeoutError,
        asyncio.LimitOverrunError,
    ) as error:
        print(f"Rejected packet: {error}")
        response = {"status": "rejected"}

    except Exception as error:
        # Log unexpected errors without leaking details to clients.
        print(f"Receiver error: {type(error).__name__}")
        response = {"status": "error"}

    try:
        writer.write(
            (json.dumps(response) + "\n").encode("utf-8")
        )
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def start_receiver():
    """
    Start a local Unix domain socket server.
    """

    directory = SOCKET_PATH.parent

    # Use the private data directory created previously.
    if not directory.is_dir():
        raise RuntimeError("NetScope data directory is missing.")

    directory_stat = directory.stat()

    if directory_stat.st_uid != os.getuid():
        raise RuntimeError("Data directory owner is incorrect.")

    if stat.S_IMODE(directory_stat.st_mode) != 0o700:
        raise RuntimeError("Data directory must have 700 permissions.")

    # Do not overwrite an existing socket or filesystem entry.
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        raise RuntimeError(
            "Socket path already exists. Check for another receiver."
        )

    # Ensure the socket is created with private permissions.
    previous_umask = os.umask(0o177)

    try:
        server = await asyncio.start_unix_server(
            handle_connection,
            path=str(SOCKET_PATH),
            limit=MAX_MESSAGE_BYTES,
        )
    finally:
        os.umask(previous_umask)

    os.chmod(SOCKET_PATH, 0o600)

    print("===== NetScope Packet Receiver =====")
    print(f"Socket: {SOCKET_PATH}")
    print("Listening for local packet metadata...")

    try:
        async with server:
            await server.serve_forever()
    finally:
        # Close and remove the socket when the receiver stops.
        server.close()
        await server.wait_closed()
        SOCKET_PATH.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        asyncio.run(start_receiver())
    except KeyboardInterrupt:
        print("\nPacket receiver stopped.")
