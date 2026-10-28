
import asyncio
import sys

from pathlib import Path

import pytest


# Allow tests to import backend modules.
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from packet_broadcaster import PacketBroadcaster


def test_subscribe_and_unsubscribe():
    broadcaster = PacketBroadcaster()

    queue = broadcaster.subscribe()

    assert broadcaster.subscriber_count == 1
    assert queue in broadcaster.subscribers

    broadcaster.unsubscribe(queue)

    assert broadcaster.subscriber_count == 0


def test_publish_to_multiple_subscribers():
    broadcaster = PacketBroadcaster()

    first_queue = broadcaster.subscribe()
    second_queue = broadcaster.subscribe()

    packet = {
        "protocol": "TCP",
        "size": 120,
    }

    broadcaster.publish(packet)

    assert first_queue.get_nowait() == packet
    assert second_queue.get_nowait() == packet


def test_publish_without_subscribers():
    broadcaster = PacketBroadcaster()

    broadcaster.publish({
        "protocol": "UDP",
        "size": 80,
    })

    assert broadcaster.subscriber_count == 0


def test_full_queue_drops_oldest_packet():
    broadcaster = PacketBroadcaster(max_queue_size=2)

    queue = broadcaster.subscribe()

    broadcaster.publish({"size": 100})
    broadcaster.publish({"size": 200})
    broadcaster.publish({"size": 300})

    # The oldest packet is discarded.
    assert queue.qsize() == 2

    assert queue.get_nowait() == {"size": 200}
    assert queue.get_nowait() == {"size": 300}


def test_unsubscribed_client_receives_no_new_packets():
    broadcaster = PacketBroadcaster()

    queue = broadcaster.subscribe()

    broadcaster.unsubscribe(queue)

    broadcaster.publish({
        "protocol": "ICMP",
        "size": 100,
    })

    assert queue.empty()


@pytest.mark.parametrize(
    "queue_size",
    [
        0,
        -1,
        True,
        1.5,
    ],
)
def test_invalid_queue_size(queue_size):
    with pytest.raises(ValueError):
        PacketBroadcaster(max_queue_size=queue_size)


def test_async_subscriber_receives_packet():
    async def run_test():
        broadcaster = PacketBroadcaster()

        queue = broadcaster.subscribe()

        packet = {
            "protocol": "TCP",
            "size": 150,
        }

        # Publish the packet.
        broadcaster.publish(packet)

        # Simulate a WebSocket subscriber waiting for data.
        received = await asyncio.wait_for(
            queue.get(),
            timeout=1,
        )

        assert received == packet

    asyncio.run(run_test())
