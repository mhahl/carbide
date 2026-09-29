"""In-process event bus plus a log ring buffer, feeding the console's
Server-Sent-Events streams. Publishers (pool, API, tailer) hand the bus
plain data dicts; rendering stays in the web views.
"""
import asyncio
import collections
import logging


class EventBus:
    def __init__(self, maxsize: int = 200):
        self._subs: set = set()
        self._maxsize = maxsize

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._maxsize)
        self._subs.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        self._subs.discard(queue)

    @property
    def subscribers(self) -> int:
        return len(self._subs)

    def publish(self, name: str, data: dict | None = None):
        event = {"name": name, "data": data or {}}
        for queue in list(self._subs):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()  # drop oldest, keep the stream live
                except asyncio.QueueEmpty:
                    pass
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    pass


class LogRingHandler(logging.Handler):
    """Keeps the last N formatted log lines and mirrors each new one
    onto the bus as a ``log`` event."""

    def __init__(self, bus=None, capacity: int = 500):
        super().__init__()
        self._bus = bus
        self._ring: collections.deque = collections.deque(maxlen=capacity)
        self.setFormatter(logging.Formatter(
            "%(asctime)s %(name)s %(levelname)s %(message)s"))

    def emit(self, record: logging.LogRecord):
        try:
            line = self.format(record)
        except Exception:
            return
        self._ring.append(line)
        if self._bus is not None:
            self._bus.publish("log", {"line": line})

    def lines(self, limit: int = 200) -> list:
        return list(self._ring)[-limit:]
