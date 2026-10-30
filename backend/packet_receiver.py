
import asyncio
import ipaddress
import json
import os
import stat
import socket
import errno
import fcntl

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



async def handle_connection(reader, writer, on_packet=None):
    """
    Receive and validate one newline-delimited JSON record.

    Optionally forward valid packet metadata to a callback.
    """

    try:
        # Read one bounded JSON message.
        packet = await read_packet_message(reader)

        # Reject invalid packet metadata.
        validate_packet(packet)

        # Forward only validated packet metadata.
        if on_packet is not None:
            on_packet(packet)

        print(
            f"Accepted {packet['protocol']} packet "
            f"({packet['size']} bytes)"
        )

        response = {"status": "accepted"}

    except ValueError as error:
        print(f"Rejected packet: {error}")
        response = {"status": "rejected"}

    except Exception as error:
        print(f"Receiver error: {type(error).__name__}")
        response = {"status": "error"}

    try:
        # Return an acknowledgment.
        writer.write(
            (json.dumps(response) + "\n").encode("utf-8")
        )
        await writer.drain()

    except (ConnectionError, OSError):
        pass

    finally:
        writer.close()

        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


def make_limited_handler(
    max_connections=MAX_CONNECTIONS,
    on_packet=None,
):
    """
    Wrap the packet receiver with a connection limit.

    Optionally forward validated packets to a callback.
    """

    if type(max_connections) is not int or max_connections < 1:
        raise ValueError(
            "Maximum connections must be a positive integer."
        )

    active_connections = 0

    async def limited_handler(reader, writer):
        nonlocal active_connections

        # Reject connections when the receiver is at capacity.
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

        # Reserve one connection slot.
        active_connections += 1

        try:
            # Process the packet and optionally broadcast it.
            await handle_connection(
                reader,
                writer,
                on_packet=on_packet,
            )

        finally:
            # Always release the connection slot.
            active_connections -= 1

    return limited_handler


def acquire_receiver_lock(directory):
    """
    Prevent multiple NetScope receivers from starting
    or recovering the same socket simultaneously.

    Keep the returned descriptor open for the entire
    receiver lifetime.
    """

    lock_path = directory / "netscope.lock"

    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW

    # Restrict newly created lock files to their owner.
    descriptor = os.open(lock_path, flags, 0o600)

    try:
        info = os.fstat(descriptor)

        # Reject unexpected file types, owners, or modes.
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise RuntimeError(
                "Receiver lock file has unsafe ownership "
                "or permissions."
            )

        try:
            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )

        except BlockingIOError as error:
            raise RuntimeError(
                "Another NetScope receiver holds "
                "the startup lock."
            ) from error

        return descriptor

    except BaseException:
        os.close(descriptor)
        raise


def recover_stale_socket(socket_path):
    """
    Recover an unused Unix socket only when it can
    be verified as stale.

    Must be called while holding the receiver lock.
    """

    try:
        info = socket_path.lstat()
    except FileNotFoundError:
        # No existing socket needs recovery.
        return False

    # Refuse symbolic links, ordinary files, and
    # any other unexpected filesystem entry.
    if not stat.S_ISSOCK(info.st_mode):
        raise RuntimeError(
            "Socket path contains a non-socket entry."
        )

    # Only inspect sockets owned by the current user.
    if info.st_uid != os.getuid():
        raise RuntimeError(
            "Existing socket has an unexpected owner."
        )

    # Require the expected private socket permissions.
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError(
            "Existing socket has unsafe permissions."
        )

    original_identity = (info.st_dev, info.st_ino)

    # Attempt to connect to the existing socket.
    with socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    ) as probe:
        probe.settimeout(0.5)

        try:
            probe.connect(str(socket_path))

        except OSError as error:
            if error.errno == errno.ENOENT:
                # The socket disappeared during inspection.
                return False

            if error.errno != errno.ECONNREFUSED:
                # Permission errors, timeouts, and uncertain
                # states must not trigger automatic deletion.
                raise RuntimeError(
                    "Could not safely verify the existing "
                    "Unix socket."
                ) from error

        else:
            # A successful connection indicates that some
            # process is accepting connections.
            raise RuntimeError(
                "An active Unix socket listener already "
                "exists."
            )

    # Connection was refused. Recheck the socket's
    # filesystem identity before attempting removal.
    current = socket_path.lstat()

    if (
        not stat.S_ISSOCK(current.st_mode)
        or current.st_uid != os.getuid()
        or (current.st_dev, current.st_ino)
        != original_identity
    ):
        raise RuntimeError(
            "Socket changed during stale-socket recovery."
        )

    # Remove the verified stale socket.
    socket_path.unlink()

    print("Recovered stale NetScope Unix socket.")

    return True


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



async def start_receiver(on_packet=None, ready_event=None):
    """
    Start NetScope's private Unix socket receiver.

    Recover verified stale sockets while protecting
    active receivers with an exclusive file lock.
    """

    directory = SOCKET_PATH.parent

    # Reject symbolic-link data directories.
    if directory.is_symlink():
        raise RuntimeError(
            "Data directory must not be a symbolic link."
        )

    if not directory.is_dir():
        raise RuntimeError(
            "NetScope data directory is missing."
        )

    directory_stat = directory.stat()

    # Verify ownership and private permissions.
    if directory_stat.st_uid != os.getuid():
        raise RuntimeError(
            "Data directory owner is incorrect."
        )

    if stat.S_IMODE(directory_stat.st_mode) != 0o700:
        raise RuntimeError(
            "Data directory must have 700 permissions."
        )

    # Obtain the exclusive receiver lock before
    # inspecting or modifying the socket path.
    lock_descriptor = acquire_receiver_lock(directory)

    server = None
    listener = None
    socket_identity = None

    try:
        # Recover only a verified stale Unix socket.
        recover_stale_socket(SOCKET_PATH)

        # Create the underlying socket ourselves.
        listener = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )

        # Use private permissions while creating
        # the socket filesystem entry.
        previous_umask = os.umask(0o177)

        try:
            # Binding creates the socket path.
            listener.bind(str(SOCKET_PATH))

            socket_info = SOCKET_PATH.lstat()

            socket_identity = (
                socket_info.st_dev,
                socket_info.st_ino,
            )

            # Restrict access to the owning user.
            os.chmod(SOCKET_PATH, 0o600)

        finally:
            # Restore the original process umask.
            os.umask(previous_umask)

        listener.listen(5)
        listener.setblocking(False)

        # Pass the pre-bound socket to asyncio.
        server = await asyncio.start_unix_server(
            make_limited_handler(
                max_connections=MAX_CONNECTIONS,
                on_packet=on_packet,
            ),
            sock=listener,
            limit=MAX_MESSAGE_BYTES + 1,
        )

        # asyncio now owns the listener.
        listener = None

        print("===== NetScope Packet Receiver =====")
        print(f"Socket: {SOCKET_PATH}")
        print("Listening for local packet metadata...")
        print("NetScope packet receiver is ready.")

        async with server:
            # Inform FastAPI that startup succeeded.
            if ready_event is not None:
                ready_event.set()

            await server.serve_forever()

    finally:
        # Close an untransferred socket if startup failed.
        if listener is not None:
            listener.close()

        # Stop the asyncio server if it was created.
        if server is not None:
            server.close()
            await server.wait_closed()

        # Remove only the socket created by this process.
        if socket_identity is not None:
            remove_owned_socket(
                SOCKET_PATH,
                socket_identity,
            )

        # Release the lock after socket cleanup.
        try:
            fcntl.flock(
                lock_descriptor,
                fcntl.LOCK_UN,
            )
        finally:
            os.close(lock_descriptor)


if __name__ == "__main__":
    try:
        asyncio.run(start_receiver())
    except KeyboardInterrupt:
        print("\nPacket receiver stopped.")
