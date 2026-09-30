"""Sensor SSH management: env rendering, and push/restart/provision
against a fake asyncssh transport (no real SSH).
"""
import os
import tempfile
import unittest
from unittest import mock

from carbide.common.config import validate
from carbide.server.web import sshmgmt
from carbide.server.web.sshmgmt import (
    MgmtError, SensorManager, passwords_from_text, toml_str_list,
    valid_image_tag)


def make_config(**over):
    mgmt = {"enabled": True, "key_path": "/tmp/fake-key",
            "user": "carbide"}
    mgmt.update(over)
    return validate({
        "role": "server",
        "server": {"sensor_token": "tok", "db_dsn": "x",
                   "blob_dir": "y"},
        "podman": {"image": "img"},
        "affinity": {},
        "sensor_mgmt": mgmt,
    })


SENSOR = {
    "sensor_id": "s1", "ssh_host": "10.0.0.9", "ssh_port": 22,
    "ssh_user": "", "remote_dir": "/root/s9",
    "listen_addr": "0.0.0.0", "listen_port": 2222,
    "server_host": "10.8.0.1", "server_port": 8440,
    "auth_passwords": '["password", "123456"]',
    "accept_probability": 0.05, "image_tag": "0.2.4",
}


class FakeResult:
    def __init__(self, output="setup ok"):
        self.exit_status = 0
        self.stdout = output
        self.stderr = ""


class FakeSFTPFile:
    def __init__(self, store, path):
        self._store = store
        self._path = path

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def write(self, data):
        self._store[self._path] = data


class FakeSFTP:
    def __init__(self):
        self.puts = []
        self.writes = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def put(self, local, remote):
        self.puts.append((local, remote))

    def open(self, path, _mode):
        return FakeSFTPFile(self.writes, path)


class FakeConn:
    def __init__(self):
        self.runs = []
        self.sftp = FakeSFTP()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def run(self, command, timeout=None):
        self.runs.append(command)
        return FakeResult()

    def start_sftp_client(self):
        return self.sftp


class MgmtTest(unittest.IsolatedAsyncioTestCase):
    def test_toml_escaping(self):
        self.assertEqual(
            toml_str_list(['a"b', "c\\d", "e,f"]),
            '"a\\"b", "c\\\\d", "e,f"')
        self.assertEqual(passwords_from_text("a\n\n b \n"), ["a", "b"])

    def test_render_env(self):
        mgr = SensorManager(make_config(), "tok")
        env = mgr.render_env(SENSOR)
        self.assertIn("SENSOR_ID=s1", env)
        self.assertIn("SENSOR_TOKEN=tok", env)
        self.assertIn("AUTH_PASSWORDS='\"password\", \"123456\"'", env)
        self.assertIn("ACCEPT_PROBABILITY=0.05", env)
        self.assertIn("TAG=0.2.4", env)

    def test_valid_image_tag(self):
        self.assertEqual(valid_image_tag(None), "latest")
        self.assertEqual(valid_image_tag(""), "latest")
        self.assertEqual(valid_image_tag("  "), "latest")
        self.assertEqual(valid_image_tag("0.2.4"), "0.2.4")
        self.assertEqual(valid_image_tag("v1_beta.rc-1"), "v1_beta.rc-1")
        for bad in ("a b", "a;b", "a/b", "-x", ".x", "x" * 129,
                    "$(x)", "`x`"):
            with self.subTest(tag=bad):
                with self.assertRaises(MgmtError):
                    valid_image_tag(bad)

    def test_files_dir_missing(self):
        mgr = SensorManager(make_config(files_dir="/tmp/nope-xyz"), "tok")
        with self.assertRaises(MgmtError):
            mgr.files_dir()

    async def test_restart_command(self):
        mgr = SensorManager(make_config(), "tok")
        captured = {}

        async def fake_connect(*args, **kwargs):
            conn = FakeConn()
            captured["conn"] = conn
            captured["kwargs"] = kwargs
            return conn

        with mock.patch.object(sshmgmt.asyncssh, "connect",
                               fake_connect):
            result = await mgr.restart(SENSOR)
        self.assertTrue(result["ok"])
        self.assertEqual(captured["kwargs"]["username"], "carbide")
        self.assertEqual(len(captured["conn"].runs), 1)
        self.assertIn("./setup.sh --skip-pull --skip-firewall",
                      captured["conn"].runs[0])
        self.assertIn("cd /root/s9", captured["conn"].runs[0])

    async def test_push_config(self):
        mgr = SensorManager(make_config(), "tok")
        captured = {}

        async def fake_connect(*args, **kwargs):
            conn = FakeConn()
            captured["conn"] = conn
            return conn

        with mock.patch.object(sshmgmt.asyncssh, "connect",
                               fake_connect):
            result = await mgr.push_config(SENSOR)
        self.assertTrue(result["ok"])
        cmd = captured["conn"].runs[0]
        self.assertIn("cat >> .env", cmd)
        self.assertIn("AUTH_PASSWORDS='\"password\", \"123456\"'", cmd)
        self.assertIn("ACCEPT_PROBABILITY=0.05", cmd)
        self.assertIn("TAG=0.2.4", cmd)
        # Push must pull (a changed image updates the container via
        # setup.sh's force-recreate); only the firewall stays skipped.
        self.assertIn("./setup.sh --skip-firewall", cmd)
        self.assertNotIn("--skip-pull", cmd)

    async def test_update_image(self):
        mgr = SensorManager(make_config(), "tok")
        captured = {}

        async def fake_connect(*args, **kwargs):
            conn = FakeConn()
            captured["conn"] = conn
            return conn

        with mock.patch.object(sshmgmt.asyncssh, "connect",
                               fake_connect):
            result = await mgr.update_image(SENSOR)
        self.assertTrue(result["ok"])
        cmd = captured["conn"].runs[0]
        # Tag persisted via --tag; no config fragment pushed.
        self.assertIn("./setup.sh --tag 0.2.4 --skip-firewall", cmd)
        self.assertNotIn("cat >>", cmd)
        self.assertNotIn("--skip-pull", cmd)
        with self.assertRaises(MgmtError):
            await mgr.update_image({**SENSOR, "image_tag": "a;b"})

    async def test_provision(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for name in sshmgmt.SENSOR_FILES:
            with open(os.path.join(tmp.name, name), "w") as fh:
                fh.write(f"# {name}\n")
        mgr = SensorManager(make_config(files_dir=tmp.name), "tok")
        captured = {}

        async def fake_connect(*args, **kwargs):
            conn = FakeConn()
            captured["conn"] = conn
            return conn

        with mock.patch.object(sshmgmt.asyncssh, "connect",
                               fake_connect):
            result = await mgr.provision(SENSOR)
        self.assertTrue(result["ok"])
        conn = captured["conn"]
        self.assertEqual(len(conn.sftp.puts), 4)
        env = conn.sftp.writes["/root/s9/.env"]
        self.assertIn("SENSOR_ID=s1", env)
        self.assertIn("TAG=0.2.4", env)
        self.assertTrue(any("./setup.sh" in run and "--skip" not in run
                            for run in conn.runs))

    async def test_disabled(self):
        mgr = SensorManager(make_config(enabled=False), "tok")
        self.assertFalse(mgr.enabled)
        with self.assertRaises(MgmtError):
            await mgr.restart(SENSOR)
