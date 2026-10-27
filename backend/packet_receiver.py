
import asyncio
import ipaddress
import json
import os
import stat
import socket

from datetime import datetime
from pathlib import Path


# Store the socket inside NetScope's private data directory.
BASE_DIR = Path(__file__).resolve().parent.parent
SOCKET_PATH = BASE_DIR / "data" / "netscope.sock"

# Maximum size of one packet metadata message.
MAX_MESSAGE_BYTES = 4096

# Maximum number of simultaneous client connections.
MAX_CONNECTIONS = 20

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


async def read_packet_message(reader):
    """
    Read one bounded, newline-delimited JSON message.

    Reject oversized, incomplete, or stalled messages.
    """

    try:
        # Wait for one complete newline-delimited message.
        message = await asyncio.wait_for(
            reader.readuntil(b"\n"),
            timeout=5,
        )

    except asyncio.TimeoutError as error:
        raise ValueError(
            "Timed out waiting for packet metadata."
        ) from error

    except asyncio.IncompleteReadError as error:
        raise ValueError(
            "Incomplete packet message."
        ) from error

    except asyncio.LimitOverrunError as error:
        raise ValueError(
            "Packet message exceeds reader limit."
        ) from error

    # Reject empty or oversized messages.
    if len(message) <= 1 or len(message) > MAX_MESSAGE_BYTES:
        raise ValueError(
            "Packet message size is invalid."
        )

    try:
        return json.loads(message.decode("utf-8"))

    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(
            "Packet message is not valid JSON."
        ) from error


async def handle_connection(reader, writer):
    """
    Receive and validate one newline-delimited JSON record.
    """

    try:
        # Read one complete, bounded JSON message.
        packet = await read_packet_message(reader)

        # Validate the extracted packet metadata.
        validate_packet(packet)

        # Display basic information about the accepted packet.
        print(
            f"Accepted {packet['protocol']} packet "
            f"({packet['size']} bytes)"
        )

        response = {"status": "accepted"}

    except ValueError as error:
        # Reject invalid, incomplete, or oversized messages.
        print(f"Rejected packet: {error}")
        response = {"status": "rejected"}

    except Exception as error:
        # Handle unexpected errors without exposing details.
        print(f"Receiver error: {type(error).__name__}")
        response = {"status": "error"}

    try:
        # Send an acknowledgment to the client.
        writer.write(
            (json.dumps(response) + "\n").encode("utf-8")
        )
        await writer.drain()

    except (ConnectionError, OSError):
        # The client may have disconnected already.
        pass

    finally:
        # Close the connection after processing the message.
        writer.close()

        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


def make_limited_handler(max_connections=MAX_CONNECTIONS):
    """
    Wrap the packet receiver with a connection limit.

    The returned callback tracks active connections
    belonging to one asyncio server instance.
    """

    if type(max_connections) is not int or max_connections < 1:
        raise ValueError(
            "Maximum connections must be a positive integer."
        )

    active_connections = 0

    async def limited_handler(reader, writer):
        nonlocal active_connections

        # Reject clients when the receiver is at capacity.
        if active_connections >= max_connections:
            try:
                response = {"status": "busy"}

                writer.write(
                    (json.dumps(response) + "\n").encode("utf-8")
                )

                await asyncio.wait_for(
                    writer.drain(),
                    timeout=1,
                )

            except (ConnectionError, OSError, asyncio.TimeoutError):
                pass

            finally:
                writer.close()

                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass

            return

        # Reserve one active connection slot.
        active_connections += 1

        try:
            # Use our existing bounded packet handler.
            await handle_connection(reader, writer)

        finally:
            # Always release the slot.
            active_connections -= 1

    return limited_handler


def remove_owned_socket(socket_path, original_identity):
    """
    Remove a socket only if its device and inode
    still match the socket created by this process.
    """

    try:
        current = socket_path.lstat()

    except FileNotFoundError:
        return

    current_identity = (
        current.st_dev,
        current.st_ino,
    )

    # Never remove a replacement filesystem entry.
    if (
        current_identity != original_identity
        or not stat.S_ISSOCK(current.st_mode)
    ):
        return

    socket_path.unlink()

    """
    Remove the socket only if its filesystem identity
    still matches the socket created by this receiver.
    """

    try:
        current = socket_path.lstat()

    except FileNotFoundError:
        return

    # Do not remove a replacement filesystem entry.
    if (
        current.st_ino != original_inode
        or not stat.S_ISSOCK(current.st_mode)
    ):
        return

    socket_path.unlink()


async def start_receiver():
    """
    Start a private Unix domain socket server.

    Bind the socket directly to avoid asyncio's automatic
    removal of an existing Unix socket path.
    """

    directory = SOCKET_PATH.parent

    # Verify the directory is not a symbolic link.
    if directory.is_symlink():
        raise RuntimeError(
            "Data directory must not be a symbolic link."
        )

    if not directory.is_dir():
        raise RuntimeError(
            "NetScope data directory is missing."
        )

    directory_stat = directory.stat()

    # Verify ownership and directory permissions.
    if directory_stat.st_uid != os.getuid():
        raise RuntimeError(
            "Data directory owner is incorrect."
        )

    if stat.S_IMODE(directory_stat.st_mode) != 0o700:
        raise RuntimeError(
            "Data directory must have 700 permissions."
        )

    # Refuse an existing file, socket, or symbolic link.
    if SOCKET_PATH.is_symlink() or os.path.lexists(SOCKET_PATH):
        raise RuntimeError(
            "Socket path already exists. "
            "Check for another receiver."
        )

    # Create the underlying Unix socket ourselves.
    listener = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )

    server = None
    socket_identity = None

    previous_umask = os.umask(0o177)

    try:
        # Bind does not automatically unlink an existing path.
        listener.bind(str(SOCKET_PATH))

        # Remember the socket's filesystem identity.
        socket_info = SOCKET_PATH.lstat()
        socket_identity = (
            socket_info.st_dev,
            socket_info.st_ino,
        )

        # Restrict access to the owning user.
        os.chmod(SOCKET_PATH, 0o600)

        # Prepare for incoming connections.
        listener.listen(5)
        listener.setblocking(False)

        # Pass the already-bound socket to asyncio.
        server = await asyncio.start_unix_server(
            make_limited_handler(),
            sock=listener,
            limit=MAX_MESSAGE_BYTES + 1,
        )

        # asyncio now owns the listener.
        listener = None

    finally:
        os.umask(previous_umask)

        # If startup failed, close our remaining socket.
        if server is None:
            listener.close()

            if socket_identity is not None:
                remove_owned_socket(
                    SOCKET_PATH,
                    socket_identity,
                )

    try:
        print("===== NetScope Packet Receiver =====")
        print(f"Socket: {SOCKET_PATH}")
        print("Listening for local packet metadata...")

        async with server:
            await server.serve_forever()

    finally:
        server.close()
        await server.wait_closed()

        # Remove only the socket created by this process.
        remove_owned_socket(
            SOCKET_PATH,
            socket_identity,
        )


if __name__ == "__main__":
    try:
        asyncio.run(start_receiver())
    except KeyboardInterrupt:
        print("\nPacket receiver stopped.")
