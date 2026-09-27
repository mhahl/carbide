import asyncio
import os
import tempfile
import unittest

from carbide.common import protocol
from carbide.sensor.server_client import ServerError, ServerLink
from carbide.sensor.spool import Spool


class FakeServer:
    """Minimal carbide-server stand-in speaking the same framing."""

    def __init__(self, token="tok", attacker_map=None):
        self.token = token
        self.attacker_map = attacker_map or {}
        self.records = []
        self.hellos = 0
        self._server = None
        self._handlers = set()

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0)
        return self._server.sockets[0].getsockname()[1]

    async def stop(self):
        # wait_closed() hangs while connections are open: drop them first,
        # like the real ServerAPI.run drain.
        for task in list(self._handlers):
            task.cancel()
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, reader, writer):
        task = asyncio.current_task()
        self._handlers.add(task)
        authed = False
        try:
            while True:
                line = await reader.readline()
                if not line:
                    return
                msg = protocol.decode(line)
                if msg["type"] == "hello":
                    if msg.get("token") != self.token:
                        reply = {"type": "reply", "in_reply_to": msg["id"], "ok": False,
                                 "error": "bad token"}
                    else:
                        authed = True
                        self.hellos += 1
                        reply = {"type": "reply", "in_reply_to": msg["id"], "ok": True}
                    writer.write(protocol.encode(reply))
                    await writer.drain()
                    if not authed:
                        return
                elif not authed:
                    return
                elif msg["type"] == "container_for":
                    info = self.attacker_map.get(
                        msg["attacker_ip"], {"container_id": "c-new"})
                    reply = {"type": "reply", "in_reply_to": msg["id"], "ok": True, **info}
                    writer.write(protocol.encode(reply))
                    await writer.drain()
                elif msg["type"] == "record":
                    self.records.append(msg["record"])
                    reply = {"type": "reply", "in_reply_to": msg["id"], "ok": True}
                    writer.write(protocol.encode(reply))
                    await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            self._handlers.discard(asyncio.current_task())
            writer.close()


class ServerLinkTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.spool = Spool(os.path.join(self.tmp.name, "spool"))
        self.fake = FakeServer()
        self.port = await self.fake.start()
        self.link = ServerLink("127.0.0.1", self.port, "s1", "tok",
                               self.spool, request_timeout=2.0)
        await self.link.start()
        for _ in range(100):
            if self.link.connected:
                break
            await asyncio.sleep(0.05)
        self.assertTrue(self.link.connected)

    async def asyncTearDown(self):
        await self.link.stop()
        await self.fake.stop()
        self.tmp.cleanup()

    async def test_container_for(self):
        reply = await self.link.container_for("9.9.9.9")
        self.assertEqual(reply["container_id"], "c-new")

    async def test_record_forwarded_and_acked(self):
        self.spool.append({"kind": "ping", "n": 1})
        self.link.nudge()
        for _ in range(100):
            if len(self.spool) == 0:
                break
            await asyncio.sleep(0.05)
        self.assertEqual(len(self.spool), 0)
        self.assertEqual(len(self.fake.records), 1)
        self.assertEqual(self.fake.records[0]["kind"], "ping")

    async def test_reconnect_resends_unacked(self):
        await self.fake.stop()  # drop the link mid-flight
        self.spool.append({"kind": "held", "n": 2})
        await asyncio.sleep(0.3)
        self.fake = FakeServer()
        port = await self.fake.start()
        self.link._port = port
        for _ in range(200):
            if len(self.spool) == 0:
                break
            await asyncio.sleep(0.05)
        self.assertEqual(len(self.spool), 0)
        self.assertEqual(
            [r["kind"] for r in self.fake.records], ["held"])

    async def test_container_for_fails_when_down(self):
        await self.fake.stop()
        await self.link.stop()
        with self.assertRaises(ServerError):
            await self.link.container_for("1.1.1.1")

    async def test_close_reader_retrieves_failed_task(self):
        import gc
        loop = asyncio.get_running_loop()
        errors = []
        loop.set_exception_handler(
            lambda _loop, ctx: errors.append(ctx))
        try:
            async def boom():
                raise ServerError("server closed connection")

            task = asyncio.create_task(boom())
            await asyncio.sleep(0)  # let it fail
            self.assertTrue(task.done())
            ServerLink._close_reader(task)
            del task
            gc.collect()
            await asyncio.sleep(0.1)
        finally:
            loop.set_exception_handler(None)
        bad = [c for c in errors
               if "never retrieved" in c.get("message", "")]
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
