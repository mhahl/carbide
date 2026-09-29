"""Console event bus + log ring buffer."""
import logging
import unittest

from carbide.server.bus import EventBus, LogRingHandler


class BusTest(unittest.TestCase):
    def test_publish_subscribe(self):
        import asyncio

        async def go():
            bus = EventBus()
            queue = bus.subscribe()
            self.assertEqual(bus.subscribers, 1)
            bus.publish("session.started", {"id": "s"})
            event = await queue.get()
            self.assertEqual(event["name"], "session.started")
            self.assertEqual(event["data"], {"id": "s"})
            bus.unsubscribe(queue)
            self.assertEqual(bus.subscribers, 0)

        asyncio.run(go())

    def test_slow_subscriber_does_not_block(self):
        import asyncio

        async def go():
            bus = EventBus(maxsize=2)
            queue = bus.subscribe()
            for i in range(5):
                bus.publish("x", {"i": i})
            self.assertEqual(queue.qsize(), 2)
            last = None
            while not queue.empty():
                last = await queue.get()
            self.assertEqual(last["data"], {"i": 4})

        asyncio.run(go())


class LogRingTest(unittest.TestCase):
    def test_ring_and_mirror(self):
        import asyncio

        async def go():
            bus = EventBus()
            handler = LogRingHandler(bus, capacity=3)
            queue = bus.subscribe()
            for i in range(5):
                handler.emit(logging.LogRecord(
                    "t", logging.INFO, __file__, 1, f"line{i}",
                    None, None))
            lines = handler.lines()
            self.assertEqual(len(lines), 3)
            self.assertTrue(lines[-1].endswith("line4"))
            event = await queue.get()
            self.assertEqual(event["name"], "log")
            self.assertIn("line0", event["data"]["line"])

        asyncio.run(go())
