
import sys
import threading
import time

from pathlib import Path

import pytest


# Allow importing backend modules.
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from packet_forwarder import PacketForwarder


@pytest.fixture
def sample_packet():
    return {
        "timestamp": "2026-10-29T09:00:00.000",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.10",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 443,
        "tcp_flags": "S",
        "size": 120,
    }


def test_forwarder_sends_packet(sample_packet):
    received = []

    def fake_send(packet):
        received.append(packet)
        return True

    forwarder = PacketForwarder(
        send_function=fake_send,
    )

    forwarder.start()

    assert forwarder.enqueue(sample_packet) is True
    assert forwarder.stop(timeout=2) is True

    assert received == [sample_packet]

    stats = forwarder.get_statistics()

    assert stats["queued"] == 1
    assert stats["sent"] == 1
    assert stats["failed"] == 0
    assert stats["pending"] == 0


def test_forwarder_records_failed_delivery(sample_packet):
    def fake_send(packet):
        return False

    forwarder = PacketForwarder(
        send_function=fake_send,
    )

    forwarder.start()
    assert forwarder.enqueue(sample_packet) is True
    assert forwarder.stop(timeout=2) is True

    stats = forwarder.get_statistics()

    assert stats["sent"] == 0
    assert stats["failed"] == 1


def test_forwarder_handles_sender_exception(sample_packet):
    def fake_send(packet):
        raise ConnectionError("Receiver unavailable")

    forwarder = PacketForwarder(
        send_function=fake_send,
    )

    forwarder.start()
    assert forwarder.enqueue(sample_packet) is True
    assert forwarder.stop(timeout=2) is True

    stats = forwarder.get_statistics()

    assert stats["failed"] == 1
    assert stats["sent"] == 0


def test_forwarder_drops_packets_when_full(sample_packet):
    # Prevent the worker from draining the queue
    # until we're ready.
    release_sender = threading.Event()
    sender_started = threading.Event()

    def slow_send(packet):
        sender_started.set()
        release_sender.wait(timeout=2)
        return True

    forwarder = PacketForwarder(
        max_queue_size=1,
        send_function=slow_send,
    )

    forwarder.start()

    try:
        assert forwarder.enqueue(sample_packet) is True

        # Wait until the worker is processing packet 1.
        assert sender_started.wait(timeout=2)

        # Packet 2 fills the single pending queue slot.
        assert forwarder.enqueue(sample_packet) is True

        # Packet 3 must be dropped immediately.
        assert forwarder.enqueue(sample_packet) is False

        stats = forwarder.get_statistics()

        assert stats["dropped"] == 1
        assert stats["queued"] == 2

    finally:
        release_sender.set()
        assert forwarder.stop(timeout=3) is True


def test_forwarder_rejects_enqueue_after_stop(sample_packet):
    forwarder = PacketForwarder(
        send_function=lambda packet: True,
    )

    forwarder.start()
    assert forwarder.stop(timeout=2) is True

    assert forwarder.enqueue(sample_packet) is False


def test_forwarder_rejects_duplicate_start():
    forwarder = PacketForwarder(
        send_function=lambda packet: True,
    )

    forwarder.start()

    try:
        with pytest.raises(RuntimeError):
            forwarder.start()
    finally:
        assert forwarder.stop(timeout=2) is True


@pytest.mark.parametrize(
    "queue_size",
    [0, -1, True, 1.5],
)
def test_invalid_forwarder_queue_size(queue_size):
    with pytest.raises(ValueError):
        PacketForwarder(
            max_queue_size=queue_size,
        )


def test_forwarder_stop_timeout(sample_packet):
    release_sender = threading.Event()
    sender_started = threading.Event()

    def slow_send(packet):
        sender_started.set()
        release_sender.wait(timeout=2)
        return True

    forwarder = PacketForwarder(
        send_function=slow_send,
    )

    forwarder.start()

    try:
        assert forwarder.enqueue(sample_packet) is True
        assert sender_started.wait(timeout=2)

        # Worker is deliberately blocked.
        assert forwarder.stop(timeout=0.01) is False

        stats = forwarder.get_statistics()
        assert stats["worker_alive"] is True

    finally:
        release_sender.set()

        # Calling stop again waits for the worker.
        assert forwarder.stop(timeout=3) is True


def test_shutdown_discards_pending_packets():
    """
    Verify that a shutdown deadline accounts for
    records that could not be forwarded.
    """

    import threading

    sender_started = threading.Event()
    release_sender = threading.Event()

    def slow_send(packet):
        sender_started.set()
        release_sender.wait(timeout=3)
        return True

    forwarder = PacketForwarder(
        max_queue_size=5,
        send_function=slow_send,
    )

    packet = {"test": "metadata"}

    forwarder.start()

    try:
        # First packet enters the sending function.
        assert forwarder.enqueue(packet) is True
        assert sender_started.wait(timeout=2)

        # Two additional records remain queued.
        assert forwarder.enqueue(packet) is True
        assert forwarder.enqueue(packet) is True

        # The worker cannot finish before this deadline.
        assert forwarder.stop(timeout=0.01) is False

        stats = forwarder.get_statistics()

        assert stats["queued"] == 3
        assert stats["shutdown_dropped"] == 2
        assert stats["pending"] == 0

    finally:
        # Release the in-progress send so the worker exits.
        release_sender.set()

        assert forwarder.worker is not None
        forwarder.worker.join(timeout=3)

        assert not forwarder.worker.is_alive()


def test_in_flight_packet_accounting():
    """
    Verify that packets currently being sent are
    distinguished from pending queue records.
    """

    import threading

    sender_started = threading.Event()
    release_sender = threading.Event()

    def slow_send(packet):
        sender_started.set()
        release_sender.wait(timeout=3)
        return True

    forwarder = PacketForwarder(
        send_function=slow_send,
    )

    forwarder.start()

    try:
        assert forwarder.enqueue({"test": "packet"}) is True
        assert sender_started.wait(timeout=2)

        # The worker has taken the packet from the queue,
        # but the send operation has not completed.
        stats = forwarder.get_statistics()

        assert stats["queued"] == 1
        assert stats["pending"] == 0
        assert stats["in_flight"] == 1
        assert stats["sent"] == 0

    finally:
        release_sender.set()
        assert forwarder.stop(timeout=3) is True

    # The packet has now finished processing.
    stats = forwarder.get_statistics()

    assert stats["in_flight"] == 0
    assert stats["sent"] == 1
    assert stats["pending"] == 0
