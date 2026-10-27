
import asyncio
import json
import socket
import stat
import sys
import tempfile
from pathlib import Path
import os

import pytest

# Allow tests to import the backend modules.
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))


from packet_receiver import (
    validate_packet,
    handle_connection,
    read_packet_message,
    remove_owned_socket,
    start_receiver,
    SOCKET_PATH,
    make_limited_handler
)


@pytest.fixture
def sample_packet():
    return {
        "timestamp": "2026-10-26T19:00:00.000",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.10",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 443,
        "tcp_flags": "S",
        "size": 120,
    }


def test_valid_packet(sample_packet):
    assert validate_packet(sample_packet) == sample_packet



@pytest.mark.parametrize(
    "field,value",
    [
        ("protocol", "INVALID"),
        ("source_ip", "not-an-ip"),
        ("destination_ip", "::1"),
        ("source_port", 70000),
        ("destination_port", -1),
        ("size", 0),
        ("size", True),
        ("timestamp", "invalid-date"),
        ("tcp_flags", "X" * 20),
    ],
)
def test_invalid_packet_fields(sample_packet, field, value):
    packet = {**sample_packet, field: value}

    with pytest.raises(ValueError):
        validate_packet(packet)


def test_missing_packet_field(sample_packet):
    packet = sample_packet.copy()
    del packet["source_ip"]

    with pytest.raises(ValueError):
        validate_packet(packet)


def test_extra_packet_field(sample_packet):
    packet = {**sample_packet, "payload": "private data"}

    with pytest.raises(ValueError):
        validate_packet(packet)


def test_valid_socket_message(sample_packet):
    async def run_test():
        received = []

        async def callback(reader, writer):
            await handle_connection(reader, writer)
            received.append(True)

        server = await asyncio.start_server(
            callback,
            host="127.0.0.1",
            port=0,
        )

        try:
            port = server.sockets[0].getsockname()[1]

            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                port,
            )

            writer.write(
                (json.dumps(sample_packet) + "\n").encode()
            )
            await writer.drain()

            response = await reader.readline()

            assert json.loads(response) == {
                "status": "accepted"
            }

            writer.close()
            await writer.wait_closed()

            assert received == [True]

        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run_test())



@pytest.mark.parametrize(
    "message",
    [
        b"",
        b'{"protocol":"TCP"}',
        b"not valid json\n",
        b"\n",
        b"x" * 5000 + b"\n",
    ],
    ids=[
        "empty",
        "incomplete",
        "invalid-json",
        "newline-only",
        "oversized",
    ],
)
def test_invalid_message_framing(message):
    async def run_test():
        reader = asyncio.StreamReader(limit=4097)

        reader.feed_data(message)
        reader.feed_eof()

        with pytest.raises(ValueError):
            await read_packet_message(reader)

    asyncio.run(run_test())


def test_valid_message_reader(sample_packet):
    async def run_test():
        reader = asyncio.StreamReader(limit=4097)

        # Create a complete newline-delimited JSON message.
        message = (
            json.dumps(sample_packet) + "\n"
        ).encode("utf-8")

        reader.feed_data(message)

        packet = await read_packet_message(reader)

        assert packet == sample_packet

    asyncio.run(run_test())


def test_socket_cleanup_preserves_replacement():
    # Create a short temporary directory for the Unix socket.
    with tempfile.TemporaryDirectory(
        prefix="ns-",
        dir="/tmp",
    ) as temporary_directory:

        socket_path = Path(temporary_directory) / "test.sock"

        # Create a real Unix domain socket.
        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        ) as server:
            server.bind(str(socket_path))

            socket_info = socket_path.lstat()
            original_identity = (
                socket_info.st_dev,
                socket_info.st_ino,
            )

            # Simulate the original socket being replaced.
            socket_path.unlink()
            socket_path.write_text("replacement")

            # Cleanup should not delete the replacement file.
            remove_owned_socket(
                socket_path,
                original_identity,
            )

            assert socket_path.read_text() == "replacement"


def test_socket_cleanup_removes_original():
    # Use a short path to avoid macOS socket path limits.
    with tempfile.TemporaryDirectory(
        prefix="ns-",
        dir="/tmp",
    ) as temporary_directory:

        socket_path = Path(temporary_directory) / "test.sock"

        # Create a real Unix domain socket.
        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        ) as server:
            server.bind(str(socket_path))

            socket_info = socket_path.lstat()
            original_identity = (
                socket_info.st_dev,
                socket_info.st_ino,
            )

            # Remove the original socket.
            remove_owned_socket(
                socket_path,
                original_identity,
            )

            assert not socket_path.exists()


def test_unix_socket_connection(sample_packet):
    # Create a short temporary socket path.
    with tempfile.TemporaryDirectory(
        prefix="ns-",
        dir="/tmp",
    ) as temporary_directory:

        socket_path = Path(temporary_directory) / "test.sock"

        async def run_test():
            # Start a real Unix domain socket server.
            server = await asyncio.start_unix_server(
                handle_connection,
                path=str(socket_path),
                limit=4097,
            )

            try:
                # Connect a client through the local socket.
                reader, writer = await asyncio.open_unix_connection(
                    str(socket_path)
                )

                try:
                    # Convert the sample packet to JSON.
                    message = json.dumps(sample_packet) + "\n"

                    # Send the packet to the receiver.
                    writer.write(message.encode("utf-8"))
                    await writer.drain()

                    # Read the receiver's acknowledgment.
                    response = await asyncio.wait_for(
                        reader.readline(),
                        timeout=5,
                    )

                    assert json.loads(response) == {
                        "status": "accepted"
                    }

                finally:
                    # Close the client connection.
                    writer.close()
                    await writer.wait_closed()

            finally:
                # Stop the Unix socket server.
                server.close()
                await server.wait_closed()

                # Remove any remaining socket file.
                socket_path.unlink(missing_ok=True)

        asyncio.run(run_test())


def test_socket_permissions():
    """
    Verify that a newly created Unix socket can
    be restricted to owner-only access.
    """
    with tempfile.TemporaryDirectory(
        prefix="ns-",
        dir="/tmp",
    ) as temporary_directory:

        socket_path = Path(temporary_directory) / "test.sock"

        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        ) as server:
            server.bind(str(socket_path))

            os.chmod(socket_path, 0o600)

            socket_info = socket_path.stat()

            assert stat.S_ISSOCK(socket_info.st_mode)
            assert stat.S_IMODE(socket_info.st_mode) == 0o600
            assert socket_info.st_uid == os.getuid()


def test_socket_directory_permissions():
    """
    Verify that a private temporary directory
    uses owner-only permissions.
    """
    with tempfile.TemporaryDirectory(
        prefix="ns-",
        dir="/tmp",
    ) as temporary_directory:

        directory = Path(temporary_directory)
        directory_info = directory.stat()

        assert stat.S_IMODE(directory_info.st_mode) == 0o700
        assert directory_info.st_uid == os.getuid()


def test_socket_permissions():
    """
    Verify that a Unix socket can be restricted
    to owner-only permissions.
    """

    with tempfile.TemporaryDirectory(
        prefix="ns-",
        dir="/tmp",
    ) as temporary_directory:

        socket_path = Path(temporary_directory) / "test.sock"

        # Create a local Unix domain socket.
        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        ) as server:
            server.bind(str(socket_path))

            # Restrict access to the owning user.
            os.chmod(socket_path, 0o600)

            socket_info = socket_path.stat()

            assert stat.S_ISSOCK(socket_info.st_mode)
            assert stat.S_IMODE(socket_info.st_mode) == 0o600
            assert socket_info.st_uid == os.getuid()


def test_socket_directory_permissions():
    """
    Verify that temporary private directories
    use owner-only permissions.
    """

    with tempfile.TemporaryDirectory(
        prefix="ns-",
        dir="/tmp",
    ) as temporary_directory:

        directory = Path(temporary_directory)
        directory_info = directory.stat()

        assert stat.S_IMODE(directory_info.st_mode) == 0o700
        assert directory_info.st_uid == os.getuid()


def test_existing_socket_cannot_be_replaced(monkeypatch):
    """
    Verify that starting another receiver does not
    replace an existing Unix socket.
    """

    import packet_receiver

    with tempfile.TemporaryDirectory(
        prefix="ns-",
        dir="/tmp",
    ) as temporary_directory:

        socket_path = Path(temporary_directory) / "test.sock"

        # Create an existing socket at the target path.
        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        ) as existing_socket:

            existing_socket.bind(str(socket_path))

            original_info = socket_path.lstat()
            original_identity = (
                original_info.st_dev,
                original_info.st_ino,
            )

            # Redirect the receiver to our temporary socket.
            monkeypatch.setattr(
                packet_receiver,
                "SOCKET_PATH",
                socket_path,
            )

            async def run_test():
                with pytest.raises(RuntimeError):
                    await packet_receiver.start_receiver()

            asyncio.run(run_test())

            # The existing socket must remain unchanged.
            current_info = socket_path.lstat()

            assert stat.S_ISSOCK(current_info.st_mode)

            assert (
                current_info.st_dev,
                current_info.st_ino,
            ) == original_identity


@pytest.mark.parametrize(
    "limit",
    [
        0,
        -1,
        True,
    ],
)
def test_invalid_connection_limit(limit):
    """
    Reject connection limits that are not
    positive integers.
    """

    with pytest.raises(ValueError):
        make_limited_handler(limit)



def test_unix_socket_connection_limit(sample_packet):
    """
    Verify that a busy receiver rejects extra clients
    and accepts new clients after a slot is released.
    """

    with tempfile.TemporaryDirectory(
        prefix="ns-",
        dir="/tmp",
    ) as temporary_directory:

        socket_path = Path(temporary_directory) / "test.sock"

        async def run_test():
            # Allow only one active connection.
            server = await asyncio.start_unix_server(
                make_limited_handler(max_connections=1),
                path=str(socket_path),
                limit=4097,
            )

            try:
                # First client connects but sends no message.
                first_reader, first_writer = (
                    await asyncio.open_unix_connection(
                        str(socket_path)
                    )
                )

                try:
                    # Allow the receiver to register this client.
                    await asyncio.sleep(0.05)

                    # Second client connects while the first
                    # still occupies the only available slot.
                    second_reader, second_writer = (
                        await asyncio.open_unix_connection(
                            str(socket_path)
                        )
                    )

                    try:
                        response = await asyncio.wait_for(
                            second_reader.readline(),
                            timeout=2,
                        )

                        assert json.loads(response) == {
                            "status": "busy"
                        }

                    finally:
                        second_writer.close()
                        await second_writer.wait_closed()

                    # Finish the first client's message.
                    message = json.dumps(sample_packet) + "\n"

                    first_writer.write(message.encode("utf-8"))
                    await first_writer.drain()

                    response = await asyncio.wait_for(
                        first_reader.readline(),
                        timeout=2,
                    )

                    assert json.loads(response) == {
                        "status": "accepted"
                    }

                finally:
                    first_writer.close()
                    await first_writer.wait_closed()

                # Wait for the receiver to close the first
                # connection and release its slot.
                await asyncio.wait_for(
                    first_reader.read(),
                    timeout=2,
                )
                await asyncio.sleep(0)

                # A third client should now be accepted.
                third_reader, third_writer = (
                    await asyncio.open_unix_connection(
                        str(socket_path)
                    )
                )

                try:
                    third_writer.write(
                        (json.dumps(sample_packet) + "\n").encode(
                            "utf-8"
                        )
                    )
                    await third_writer.drain()

                    response = await asyncio.wait_for(
                        third_reader.readline(),
                        timeout=2,
                    )

                    assert json.loads(response) == {
                        "status": "accepted"
                    }

                finally:
                    third_writer.close()
                    await third_writer.wait_closed()

            finally:
                server.close()
                await server.wait_closed()
                socket_path.unlink(missing_ok=True)

        asyncio.run(run_test())
