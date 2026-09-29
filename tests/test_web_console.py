"""Console web UI: auth flow, page rendering, actions, and SSE, all
against fakes (no postgres, no podman, no SSH).
"""
import asyncio
import os
import tempfile
import unittest

from aiohttp.test_utils import TestClient, TestServer

from carbide.common.blobstore import BlobStore
from carbide.common.config import validate
from carbide.server.api import ServerAPI
from carbide.server.bus import EventBus, LogRingHandler
from carbide.server.eviction import EvictionJob
from carbide.server.forensics import Forensics
from carbide.server.pool import Pool
from carbide.server.web import auth as webauth
from carbide.server.web.webapp import create_app
from tests.fakes import FakeDatabase, FakePodman, utcnow


def make_config():
    return validate({
        "role": "server",
        "server": {"sensor_token": "tok", "db_dsn": "x", "blob_dir": "y",
                   "api_port": 8440},
        "podman": {"image": "img", "pool_size": 0,
                   "port_range_start": 22000, "port_range_end": 22010},
        "affinity": {"keep_warm_minutes": 0},
        "quotas": {"session_max_bytes": 10**6},
    })


class FakeWriter:
    def __init__(self):
        self.frames = []

    def write(self, data):
        self.frames.append(data)

    async def drain(self):
        pass


class WebConsoleTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._iters = webauth.ITERATIONS
        webauth.ITERATIONS = 1000  # keep the suite fast
        self.addCleanup(setattr, webauth, "ITERATIONS", self._iters)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = FakeDatabase()
        self.pod = FakePodman()
        cfg = make_config()
        self.blobs = BlobStore(os.path.join(self.tmp.name, "blobs"), 10**9)
        self.pool = Pool(self.pod, self.db, cfg)
        forensics = Forensics(self.pool, self.pod, self.db,
                              self.blobs, cfg)
        self.eviction = EvictionJob(self.pool, self.pod, self.db,
                                    forensics, cfg)
        self.api = ServerAPI(self.db, self.pool, forensics,
                             self.blobs, cfg)
        self.bus = EventBus()
        self.logring = LogRingHandler(self.bus)
        app = create_app({
            "cfg": cfg, "db": self.db, "pool": self.pool,
            "pod": self.pod, "blobs": self.blobs, "api": self.api,
            "forensics": forensics, "eviction": self.eviction,
            "bus": self.bus, "logring": self.logring})
        self.client = TestClient(TestServer(app))
        await self.client.start_server()
        self.addAsyncCleanup(self.client.close)
        await self.db.create_web_user(
            "admin", webauth.hash_password("password123"))

    async def login(self, username="admin", password="password123"):
        return await self.client.post(
            "/login", data={"username": username, "password": password},
            allow_redirects=False)

    async def test_login_flow(self):
        resp = await self.login(password="wrong")
        self.assertEqual(resp.status, 200)
        self.assertIn("bad username or password", await resp.text())
        resp = await self.login()
        self.assertEqual(resp.status, 302)
        self.assertEqual(resp.headers["Location"], "/")
        resp = await self.client.get("/")
        self.assertEqual(resp.status, 200)
        self.assertIn("CARBIDE CONSOLE", await resp.text())

    async def test_wireframe_theme_and_active_nav(self):
        await self.login()
        body = await (await self.client.get("/")).text()
        self.assertIn('data-theme="wireframe"', body)
        self.assertIn("html[data-theme=\"wireframe\"]", body)
        self.assertIn('href="/" class="active"', body)
        body = await (await self.client.get("/sessions")).text()
        self.assertIn('href="/sessions" class="active"', body)
        self.assertNotIn('href="/" class="active"', body)

    async def test_anonymous_redirected(self):
        resp = await self.client.get(
            "/sessions", allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertTrue(
            resp.headers["Location"].startswith("/login"))
        resp = await self.client.post(
            "/actions/sessions/x/kill", headers={"HX-Request": "true"})
        self.assertEqual(resp.status, 401)
        self.assertEqual(resp.headers["HX-Redirect"], "/login")

    async def _seed_session(self, sid="sess1"):
        await self.db.ensure_session(sid, "s1", "9.9.9.9")
        await self.db.set_session_started(sid, "root", utcnow(), "9.9.9.9")
        await self.db.add_auth_attempt(
            sid, "s1", "root", "hunter2", True, True, utcnow())
        await self.db.add_transcript(
            sid, "ch1", "in", "pty", 0, b"whoami\n", utcnow())
        ref = self.blobs.put_bytes(b"evil-tool")
        await self.db.add_blob(ref.sha256, ref.path, ref.size)
        await self.db.add_session_file(
            sid, "mimikatz.exe", ref.sha256, ref.size, utcnow())
        await self.db.add_squid_hit(
            sid, "s1", "10.89.0.2", utcnow(), "GET",
            "http://example.com/", 200, 64, "text/html")
        await self.db.add_diff_rows(sid, [("/etc/evil", "added")])
        await self.db.save_report(sid, "# report", "{}", utcnow())
        return ref

    async def test_pages_render(self):
        ref = await self._seed_session()
        await self.db.set_affinity("s1", "9.9.9.9", "fake-c1", 22001,
                                   "pw", "10.89.0.2")
        await self.db.add_snapshot("s1", "9.9.9.9", "fake-c1",
                                   "carbide-snap-x:latest")
        await self.db.upsert_managed_sensor("s1", "10.0.0.9")
        cid = self.pod.create_container(
            "carbide-fresh-abcd", "img", "honey", 22002, "carbide",
            {}, 256, 128)
        await self.login()
        for path in ("/", "/sessions", "/sessions/sess1",
                     "/sessions/sess1/transcript?after=0",
                     f"/files/{ref.sha256}/download?name=x",
                     "/snapshots", "/compare?a=sess1&b=sess1",
                     "/auth", "/podman",
                     f"/podman/containers/{cid}",
                     f"/podman/containers/{cid}/diff",
                     f"/podman/containers/{cid}/file?path=/etc/motd",
                     "/sensors", "/sensors/new", "/sensors/s1",
                     "/logs", "/users", "/fragments/containers",
                     "/fragments/sensors", "/fragments/recent-sessions"):
            with self.subTest(path=path):
                resp = await self.client.get(path)
                self.assertEqual(resp.status, 200, path)
        resp = await self.client.get("/sessions/nope")
        self.assertEqual(resp.status, 404)

    async def test_container_actions(self):
        cid = self.pod.create_container(
            "carbide-fresh-abcd", "img", "honey", 22002, "carbide",
            {}, 256, 128)
        await self.login()
        resp = await self.client.post(f"/actions/containers/{cid}/start")
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.pod.status(cid), "running")
        resp = await self.client.post(f"/actions/containers/{cid}/stop")
        self.assertIn("stop", await resp.text())
        self.assertEqual(self.pod.status(cid), "exited")

    async def test_evict_and_snapshot(self):
        await self._seed_session()
        cid = self.pod.create_container(
            "carbide-fresh-abcd", "img", "honey", 22001, "carbide",
            {}, 256, 128)
        await self.db.set_affinity("s1", "9.9.9.9", cid, 22001,
                                   "pw", "10.89.0.2")
        await self.login()
        resp = await self.client.post(
            "/actions/snapshots",
            data={"container_id": cid, "sensor_id": "s1",
                  "ip": "9.9.9.9"})
        self.assertIn("created", await resp.text())
        resp = await self.client.post(
            "/actions/affinities/evict",
            data={"sensor_id": "s1", "ip": "9.9.9.9"})
        self.assertIn("evicted", await resp.text())
        self.assertIsNone(await self.db.get_affinity("s1", "9.9.9.9"))

    async def test_kill_session(self):
        await self._seed_session()
        writer = FakeWriter()
        self.api._links["s1"] = {writer}
        await self.login()
        resp = await self.client.post("/actions/sessions/sess1/kill")
        self.assertIn("kill sent", await resp.text())
        self.assertEqual(len(writer.frames), 1)
        import json
        msg = json.loads(writer.frames[0].decode())
        self.assertEqual(msg["type"], "notify")
        self.assertEqual(msg["name"], "kill_session")
        self.assertEqual(msg["session_id"], "sess1")

    async def test_kill_without_link(self):
        await self._seed_session()
        await self.login()
        resp = await self.client.post("/actions/sessions/sess1/kill")
        self.assertIn("not connected", await resp.text())

    async def test_sensor_save_and_delete(self):
        await self.login()
        resp = await self.client.post(
            "/sensors/save",
            data={"sensor_id": "s9", "ssh_host": "10.0.0.9",
                  "accept_probability": "0.1",
                  "passwords": "a\nb"}, allow_redirects=False)
        self.assertEqual(resp.status, 302)
        row = await self.db.get_managed_sensor("s9")
        self.assertEqual(row["ssh_host"], "10.0.0.9")
        self.assertEqual(row["auth_passwords"], '["a", "b"]')
        resp = await self.client.post(
            "/sensors/s9/delete", allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIsNone(await self.db.get_managed_sensor("s9"))

    async def test_sensor_push_disabled(self):
        await self.db.upsert_managed_sensor("s1", "10.0.0.9")
        await self.login()
        resp = await self.client.post("/actions/sensors/s1/push")
        self.assertIn("not configured", await resp.text())

    async def test_user_management(self):
        await self.login()
        resp = await self.client.post(
            "/users/create",
            data={"username": "bob", "password": "password123"},
            allow_redirects=False)
        self.assertEqual(resp.status, 302)
        bob = await self.db.get_web_user_by_name("bob")
        self.assertIsNotNone(bob)
        resp = await self.client.post(
            f"/users/{bob['id']}/password",
            data={"password": "newpassword123"},
            allow_redirects=False)
        self.assertEqual(resp.status, 302)
        resp = await self.client.post(
            f"/users/{bob['id']}/disable", allow_redirects=False)
        self.assertEqual(resp.status, 302)
        # cannot disable self or the last enabled user
        admin = await self.db.get_web_user_by_name("admin")
        resp = await self.client.post(
            f"/users/{admin['id']}/disable", allow_redirects=False)
        self.assertIn("disable+self",
                      resp.headers["Location"])

    async def test_events_stream(self):
        await self.login()
        resp = await self.client.get("/events/stream")
        self.assertEqual(resp.status, 200)
        self.bus.publish("session.started", {"session_id": "s"})
        line = await asyncio.wait_for(
            resp.content.readline(), timeout=5)
        self.assertIn(b"event: session-started", line)
        body = b""
        while not body.endswith(b"\n\n"):
            body += await asyncio.wait_for(
                resp.content.readline(), timeout=5)
        self.assertIn(b"sess", body)
        resp.close()

    async def test_logs_stream_replays_ring(self):
        import logging
        await self.login()
        self.logring.emit(logging.LogRecord(
            "carbide.test", logging.INFO, __file__, 1,
            "hello-ring", None, None))
        resp = await self.client.get("/logs/stream")
        self.assertEqual(resp.status, 200)
        body = b""
        while b"hello-ring" not in body:
            body += await asyncio.wait_for(
                resp.content.readline(), timeout=5)
        self.assertIn(b"event: log", body)
        resp.close()
