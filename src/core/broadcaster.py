import asyncio

from loguru import logger


class LogBroadcaster:
    """Manages asynchronous pub/sub queues for Server-Sent Events (SSE)."""

    def __init__(self) -> None:
        self.queues: list[asyncio.Queue[str]] = []

    def subscribe(self) -> asyncio.Queue[str]:
        """Creates a new queue for an incoming SSE connection."""
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=100)
        self.queues.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        """Removes a queue when the client disconnects."""
        if queue in self.queues:
            self.queues.remove(queue)

    def write(self, message: str) -> None:
        """Sink method for Loguru to push JSON formatted logs to all subscribers."""
        for queue in self.queues:
            try:
                # Non-blocking put; drops logs for slow clients to prevent memory leaks
                queue.put_nowait(message)
            except asyncio.QueueFull:
                pass


# Global instance
log_broadcaster = LogBroadcaster()


def configure_sse_logger() -> None:
    """Attaches the broadcaster to Loguru."""
    logger.add(
        log_broadcaster.write,
        level="INFO",
        format="{message}",
        serialize=True,
        enqueue=True,  # Thread-safe bridging from sync logging to async queues
    )
