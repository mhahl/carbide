"""Pin key server-side lifecycle log lines (operators troubleshoot from
these, so silence is a regression). Also pins the redaction rule: passwords
must never appear in logs.
"""
import asyncio
import unittest

from carbide.common.config import validate
from carbide.server.api import ServerAPI
from carbide.server.eviction import EvictionJob
from carbide.server.pool import Pool
from tests.fakes import FakeDatabase, FakePodman


def make_config():
    return validate({
        "role": "server",
        "server": {"sensor_token": "tok", "db_dsn": "x", "blob_dir": "y",
                   "api_port": 8440},
        "podman": {"image": "img", "port_range_start": 22000,
                   "port_range_end": 22010},
        "affinity": {"keep_warm_minutes": 0},
    })


class ServerLoggingTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.db = FakeDatabase()
        self.pod = FakePodman()
        cfg = make_config()
        self.pool = Pool(self.pod, self.db, cfg)
        await self.pool.start()

        async def _ready(*args, **kwargs):
            return None
        self.pool._wait_sshd = _ready
        self.api = ServerAPI(self.db, self.pool, None, None, cfg)

    async def test_fresh_assignment_logged(self):
        with self.assertLogs("carbide.server.pool",
                             level="INFO") as logs:
            ep = await self.pool.container_for("s1", "1.2.3.4")
        text = "\n".join(logs.output)
        self.assertIn("assigned fresh container", text)
        self.assertIn(ep["container_id"][:12], text)

    async def test_reuse_and_removal_logged(self):
        await self.pool.container_for("s1", "1.2.3.4")
        with self.assertLogs("carbide.server.pool",
                             level="INFO") as logs:
            await self.pool.container_for("s1", "1.2.3.4")
        self.assertIn("reusing container", "\n".join(logs.output))
        with self.assertLogs("carbide.server.pool",
                             level="INFO") as logs:
            await self.pool.remove_affinity("s1", "1.2.3.4")
        self.assertIn("removed affinity s1/1.2.3.4",
                      "\n".join(logs.output))

    async def test_session_start_end_logged(self):
        with self.assertLogs("carbide.server.api", level="INFO") as logs:
            await self.api._r_session_start(
                "s1", "sess1",
                {"attacker_ip": "9.9.9.9", "username": "root"})
        self.assertIn("session sess1 started", "\n".join(logs.output))
        with self.assertLogs("carbide.server.api", level="INFO") as logs:
            await self.api._r_session_end(
                "s1", "sess1", {"reason": "done"})
        self.assertIn("session sess1 ended", "\n".join(logs.output))
        await asyncio.sleep(0.05)  # drain the keep-warm task

    async def test_auth_password_never_logged(self):
        with self.assertLogs("carbide.server.api",
                             level="DEBUG") as logs:
            await self.api._r_auth(
                "s1", "sess9",
                {"username": "root", "password": "s3cret-pw",
                 "accepted": True, "matched_list": True})
        text = "\n".join(logs.output)
        self.assertIn("auth attempt", text)
        self.assertNotIn("s3cret-pw", text)

    async def test_eviction_pass_summary_logged(self):
        job = EvictionJob(self.pool, self.pod, self.db, None,
                          make_config())
        with self.assertLogs("carbide.server.eviction",
                             level="INFO") as logs:
            await job.run_once()
        self.assertIn("eviction pass: 0 scanned, 0 evicted",
                      "\n".join(logs.output))
