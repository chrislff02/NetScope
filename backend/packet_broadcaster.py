
import asyncio


class PacketBroadcaster:
    """
    Distribute validated packet metadata to connected subscribers.

    Each subscriber receives its own bounded asyncio queue.
    Slow subscribers may miss packets rather than consuming
    unlimited memory.
    """

    def __init__(self, max_queue_size=100):
        if (
            type(max_queue_size) is not int
            or max_queue_size < 1
        ):
            raise ValueError(
                "Queue size must be a positive integer."
            )

        self.max_queue_size = max_queue_size
        self.subscribers = set()

    def subscribe(self):
        """
        Register a subscriber and return its packet queue.
        """

        queue = asyncio.Queue(
            maxsize=self.max_queue_size
        )

        self.subscribers.add(queue)

        return queue

    def unsubscribe(self, queue):
        """
        Remove a subscriber from the broadcaster.
        """

        self.subscribers.discard(queue)

    def publish(self, packet):
        """
        Publish a validated packet to all subscribers.

        When a subscriber queue is full, remove its oldest
        item to make room for the newest packet.
        """

        for queue in tuple(self.subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass

            queue.put_nowait(packet)

    @property
    def subscriber_count(self):
        """
        Return the number of active subscribers.
        """

        return len(self.subscribers)
