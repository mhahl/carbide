"""Server->sensor notifies: link dispatch plus the console kill action."""
import tempfile
import unittest

from carbide.common.config import validate
from carbide.sensor.app import SensorApp
from carbide.sensor.server_client import ServerLink


def make_link(**kwargs):
    args = {"host": "127.0.0.1", "port": 1, "sensor_id": "s1",
            "token": "t", "spool": None}
    args.update(kwargs)
    return ServerLink(**args)


class NotifyDispatchTest(unittest.IsolatedAsyncioTestCase):
    async def test_notify_dispatched(self):
        seen = []

        async def handler(msg):
            seen.append(msg)

        link = make_link(on_notify=handler)
        await link._on_notify({"type": "notify", "name": "kill_session",
                               "session_id": "s"})
        self.assertEqual(seen[0]["session_id"], "s")

    async def test_notify_without_handler_dropped(self):
        link = make_link()
        await link._on_notify({"type": "notify", "name": "whatever"})

    async def test_handler_error_swallowed(self):
        async def handler(_msg):
            raise RuntimeError("boom")

        link = make_link(on_notify=handler)
        await link._on_notify({"type": "notify", "name": "x"})


class FakeRecorder:
    def __init__(self):
        self.ends = []

    def session_end(self, reason):
        self.ends.append(reason)


class FakeConn:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeCtx:
    def __init__(self, session_id):
        self.session_id = session_id
        self.recorder = FakeRecorder()
        self.conn = FakeConn()


class KillSessionTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cfg = validate({
            "role": "sensor",
            "sensor": {
                "listen_addr": "127.0.0.1", "listen_port": 2222,
                "host_key_path": "/tmp/nope", "server_host": "127.0.0.1",
                "server_port": 8440, "sensor_id": "s1", "token": "t",
                "spool_dir": self.tmp.name},
            "auth": {"passwords": ["pw"], "accept_probability": 0.05},
        })
        self.app = SensorApp(cfg)

    async def test_kill_live_session(self):
        ctx = FakeCtx("sess1")
        self.app._ctx_by_session["sess1"] = ctx
        await self.app._handle_notify({"type": "notify",
                                       "name": "kill_session",
                                       "session_id": "sess1"})
        self.assertEqual(ctx.recorder.ends, ["killed by operator"])
        self.assertTrue(ctx.conn.closed)

    async def test_kill_unknown_session_ignored(self):
        await self.app._handle_notify({"type": "notify",
                                       "name": "kill_session",
                                       "session_id": "nope"})

    async def test_unknown_notify_ignored(self):
        await self.app._handle_notify({"type": "notify",
                                       "name": "self_destruct"})
