"""Sensor SSH banner must impersonate OpenSSH, not AsyncSSH.

nmap fingerprints the listener banner; the default AsyncSSH banner
("AsyncSSH sshd 2.24.0") outs the honeypot, so the sensor reports
"SSH-2.0-OpenSSH_10.2" instead.
"""
import asyncio
import tempfile
import unittest
from unittest import mock

from carbide.common.config import validate
from carbide.sensor import app as sensor_app


def make_config(base):
    return validate({
        "role": "sensor",
        "sensor": {"listen_addr": "127.0.0.1", "listen_port": 2222,
                   "host_key_path": base + "/hk",
                   "server_host": "127.0.0.1", "server_port": 1,
                   "sensor_id": "s1", "token": "t",
                   "spool_dir": base + "/spool"},
        "auth": {"passwords": ["x"], "accept_probability": 0.0},
    })


class SensorBannerTest(unittest.IsolatedAsyncioTestCase):
    async def test_listener_reports_openssh_banner(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        app = sensor_app.SensorApp(make_config(tmp.name))
        app.link = mock.Mock()
        app.link.start = mock.AsyncMock()
        app.link.stop = mock.AsyncMock()
        listener = mock.Mock()
        created = mock.AsyncMock(return_value=listener)
        with mock.patch.object(sensor_app.asyncssh, "create_server",
                               created):
            task = asyncio.create_task(app.run())
            try:
                for _ in range(1000):
                    if created.called:
                        break
                    await asyncio.sleep(0.01)
                self.assertTrue(created.called)
            finally:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self.assertEqual(
            created.call_args.kwargs["server_version"], "OpenSSH_10.2")
