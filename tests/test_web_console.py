"""Console web UI: auth flow, page rendering, actions, and SSE, all
against fakes (no postgres, no podman, no SSH).
"""
import asyncio
import datetime
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
from tests.fakes import FakeDatabase, FakePodman, FakeTransport, utcnow


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
            "bus": self.bus, "logring": self.logring,
            "vt_transport": FakeTransport()})
        self.app = app
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

    async def test_dashboard_geo_ptr_and_layout(self):
        await self._seed_session()
        await self.db.save_ip_intel(
            "9.9.9.9", rdns="ptr.example.com", country_code="NL",
            country="Netherlands", city="Amsterdam", org="Example ISP")
        await self.login()
        body = await (await self.client.get("/")).text()
        self.assertIn("NL · Amsterdam", body)
        self.assertIn("Example ISP", body)
        self.assertIn("ptr.example.com", body)
        self.assertIn("<th scope=\"col\">Geo</th>", body)
        self.assertIn("<th scope=\"col\">PTR</th>", body)
        # Recent sessions full-width on top, live sensors below it.
        self.assertIn(
            '<section class="card card-border bg-base-100" '
            'aria-label="Recent sessions">', body)
        self.assertLess(body.index('aria-label="Recent sessions"'),
                        body.index('aria-label="Live sensors"'))

    async def test_recent_sessions_show_evidence_counts(self):
        ref = await self._seed_session()
        await self.db.save_vt_scan(ref.sha256, "malicious", malicious=9)
        await self.db.ensure_session("bare", "s1", "9.9.9.9")
        await self.login()
        body = await (await self.client.get("/")).text()
        self.assertIn('data-sort-type="number">Files</th>', body)
        self.assertIn('data-sort-type="number">URLs</th>', body)
        self.assertIn('href="/sessions/sess1#files">1</a>', body)
        self.assertIn("1 mal</span>", body)
        self.assertIn('href="/sessions/sess1#squid">1</a>', body)
        detail = await (await self.client.get("/sessions/sess1")).text()
        self.assertIn('id="files"', detail)
        self.assertIn('id="squid"', detail)

    async def test_dashboard_attacker_map(self):
        await self._seed_session()
        await self.db.save_ip_intel(
            "9.9.9.9", country_code="NL", country="Netherlands")
        await self.login()
        body = await (await self.client.get("/")).text()
        self.assertIn('aria-label="Attacker origins"', body)
        self.assertIn("1 countries", body)
        self.assertIn(
            '<link rel="stylesheet" href="/static/leaflet.css">', body)
        self.assertIn('<script src="/static/leaflet.js"></script>', body)
        self.assertIn('id="attacker-map"', body)
        self.assertIn('"lat": 52.2', body)
        self.assertIn('"lon": 5.4', body)
        self.assertIn("Netherlands (NL): 1 attacker, 1 session", body)
        self.assertNotIn("_world_paths", body)
        self.assertIn("tiles watermarked", body)
        self.assertNotIn("api_key=", body)
        self.assertLess(body.index('aria-label="Attacker origins"'),
                        body.index('aria-label="Recent sessions"'))

    async def test_investigator_pivot_links(self):
        await self._seed_session()
        cid = self.pod.create_container(
            "carbide-test", "img", "honey", 22001, "carbide",
            {}, 256, 128)
        await self.db.set_session_container("sess1", cid, True)
        await self.db.set_affinity("s1", "9.9.9.9", cid, 22001,
                                   "pw", "10.89.0.2")
        await self.db.add_snapshot("s1", "9.9.9.9", cid,
                                   "carbide-snap-x:latest")
        await self.login()
        sessions = await (await self.client.get("/sessions")).text()
        self.assertIn('href="/attackers/9.9.9.9"', sessions)
        self.assertIn(f'href="/podman/containers/{cid}"', sessions)
        detail = await (
            await self.client.get("/sessions/sess1")).text()
        self.assertIn('href="/attackers/9.9.9.9"', detail)
        attacker = await (
            await self.client.get("/attackers/9.9.9.9")).text()
        self.assertIn(f'href="/podman/containers/{cid}"', attacker)
        container = await (
            await self.client.get(f"/podman/containers/{cid}")).text()
        self.assertIn('href="/attackers/9.9.9.9"', container)
        self.assertIn('href="/sessions?sensor=s1"', container)
        self.assertIn("Sessions on this affinity", container)
        snapshots = await (await self.client.get("/snapshots")).text()
        self.assertIn('href="/attackers/9.9.9.9"', snapshots)
        self.assertIn('href="/sessions?sensor=s1"', snapshots)
        auth = await (await self.client.get("/auth")).text()
        self.assertIn('href="/sessions?sensor=s1"', auth)
        dash = await (await self.client.get("/")).text()
        self.assertIn('href="/attackers/9.9.9.9"', dash)
        self.assertIn('href="/sessions/sess1"', dash)
        files = await (await self.client.get("/files")).text()
        self.assertIn('href="/sessions/sess1"', files)
        self.assertIn('href="/attackers/9.9.9.9"', files)
        self.assertIn('href="/sessions?sensor=s1"', files)
        self.assertIn('href="/files"', detail)
        self.assertIn('href="/files?ip=9.9.9.9"', attacker)

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
                     "/files",
                     "/snapshots", "/compare?a=sess1&b=sess1",
                     "/auth", "/podman",
                     f"/podman/containers/{cid}",
                     f"/podman/containers/{cid}/diff",
                     f"/podman/containers/{cid}/file?path=/etc/motd",
                     "/sensors", "/sensors/new", "/sensors/s1",
                     "/attackers", "/attackers/9.9.9.9",
                     "/logs", "/users", "/settings",
                     "/fragments/containers",
                     "/fragments/sensors", "/fragments/recent-sessions"):
            with self.subTest(path=path):
                resp = await self.client.get(path)
                self.assertEqual(resp.status, 200, path)
        resp = await self.client.get("/sessions/nope")
        self.assertEqual(resp.status, 404)
        resp = await self.client.get("/attackers/8.8.8.8")
        self.assertEqual(resp.status, 404)

    async def test_sessions_hide_containerless_by_default(self):
        await self._seed_session("withbox")
        await self.db.set_session_container("withbox", "c1", True)
        await self._seed_session("nobox")
        await self.login()
        body = await (await self.client.get("/sessions")).text()
        self.assertIn("withbox", body)
        self.assertNotIn("nobox", body)
        self.assertIn('name="empty"', body)
        body = await (
            await self.client.get("/sessions?empty=1")).text()
        self.assertIn("withbox", body)
        self.assertIn("nobox", body)

    async def test_ended_shows_relative_age(self):
        await self._seed_session()
        ended = utcnow() - datetime.timedelta(hours=3, minutes=5)
        await self.db.set_session_end("sess1", ended, "closed")
        await self.login()
        body = await (await self.client.get("/sessions?empty=1")).text()
        self.assertIn(
            f'<span title="{ended.strftime("%Y-%m-%d %H:%M:%S")}">'
            "3h ago</span>", body)
        detail = await (await self.client.get("/sessions/sess1")).text()
        self.assertIn(">3h ago</span>", detail)
        attacker = await (
            await self.client.get("/attackers/9.9.9.9")).text()
        self.assertIn(">3h ago</span>", attacker)

    async def test_attackers_and_verdicts(self):
        ref = await self._seed_session()
        await self.db.save_vt_scan(
            ref.sha256, "malicious", malicious=9, harmless=60,
            permalink="https://www.virustotal.com/gui/file/abc")
        await self.db.save_ip_intel(
            "9.9.9.9", rdns="evil.example.com",
            open_ports='[{"port": 22, "proto": "tcp", "service": "ssh", '
                       '"version": "OpenSSH 8.9"}]')
        await self.login()
        body = await (await self.client.get("/attackers")).text()
        self.assertIn("9.9.9.9", body)
        self.assertIn('badge-success badge-soft badge-xs">scanned</span>',
                      body)
        body = await (await self.client.get("/attackers/9.9.9.9")).text()
        self.assertIn("evil.example.com", body)
        self.assertIn("OpenSSH 8.9", body)
        self.assertIn("mimikatz.exe", body)
        self.assertIn("sess1", body)
        self.assertIn(
            'href="https://www.virustotal.com/gui/file/abc">mimikatz.exe',
            body)
        body = await (await self.client.get("/sessions/sess1")).text()
        self.assertIn("malicious", body)
        self.assertIn(
            'href="https://www.virustotal.com/gui/file/abc">mimikatz.exe',
            body)
        self.assertNotIn(">VT</a>", body)
        self.assertIn("1/1 detected", body)
        self.assertIn("xl:col-span-2", body)

    async def test_files_page_lists_verdicts_filters_and_sorts(self):
        ref = await self._seed_session()
        clean = self.blobs.put_bytes(b"benign-readme")
        await self.db.add_blob(clean.sha256, clean.path, clean.size)
        await self.db.add_session_file(
            "sess1", "readme.txt", clean.sha256, clean.size, utcnow())
        await self.db.add_session_file(
            "sess1", "dropped-partial", "", 0, utcnow())
        unknown = self.blobs.put_bytes(b"unknown-binary")
        await self.db.add_blob(unknown.sha256, unknown.path, unknown.size)
        await self.db.add_session_file(
            "sess1", "unknown.bin", unknown.sha256, unknown.size,
            utcnow())
        await self.db.save_vt_scan(
            ref.sha256, "malicious", malicious=9,
            permalink="https://www.virustotal.com/gui/file/abc")
        await self.db.save_vt_scan(clean.sha256, "clean", harmless=70)
        await self.login()
        body = await (await self.client.get("/files")).text()
        for name in ("mimikatz.exe", "readme.txt", "dropped-partial",
                     "unknown.bin"):
            self.assertIn(name, body)
        self.assertIn('href="/files" class="active"', body)
        self.assertIn(
            'href="https://www.virustotal.com/gui/file/abc"'
            ">mimikatz.exe</a>", body)
        self.assertIn("malicious", body)
        self.assertIn("unscanned", body)
        self.assertIn('href="/sessions/sess1"', body)
        self.assertIn('href="/attackers/9.9.9.9"', body)
        self.assertIn("/files?sort=verdict&amp;dir=asc", body)
        self.assertNotIn("SHA256", body)
        self.assertNotIn(">Captured", body)
        # Scan only for shas without a verdict; dropped files say so.
        self.assertIn("/actions/files/3/scan", body)
        self.assertNotIn("/actions/files/0/scan", body)
        self.assertIn(
            f"/files/{unknown.sha256}/download?name=unknown.bin", body)
        self.assertIn("dropped", body)
        # Verdict filter narrows to the matching rows.
        mal = await (
            await self.client.get("/files?verdict=malicious")).text()
        self.assertIn("mimikatz.exe", mal)
        self.assertNotIn("readme.txt", mal)
        self.assertNotIn("unknown.bin", mal)
        unsc = await (
            await self.client.get("/files?verdict=unscanned")).text()
        self.assertIn("unknown.bin", unsc)
        self.assertIn("dropped-partial", unsc)
        self.assertNotIn("mimikatz.exe", unsc)
        self.assertNotIn("readme.txt", unsc)
        # Sensor/IP filters and server-side name sort.
        self.assertIn("mimikatz.exe", await (
            await self.client.get("/files?sensor=s1")).text())
        self.assertIn("No files captured.", await (
            await self.client.get("/files?sensor=nope")).text())
        self.assertIn("No files captured.", await (
            await self.client.get("/files?ip=1.2.3.4")).text())
        by_name = await (
            await self.client.get("/files?sort=name&dir=asc")).text()
        self.assertLess(by_name.index("dropped-partial"),
                        by_name.index("mimikatz.exe"))
        self.assertLess(by_name.index("mimikatz.exe"),
                        by_name.index("readme.txt"))
        self.assertLess(by_name.index("readme.txt"),
                        by_name.index("unknown.bin"))

    async def test_attacker_unscanned_states(self):
        await self._seed_session()
        await self.login()
        body = await (await self.client.get("/attackers/9.9.9.9")).text()
        self.assertIn("nmap queued", body)
        self.assertIn("unscanned", body)
        body = await (await self.client.get("/sessions/sess1")).text()
        self.assertIn("unscanned", body)
        self.assertIn("0/1 detected", body)

    async def test_vt_key_settings_flow(self):
        await self.login()
        body = await (await self.client.get("/settings")).text()
        self.assertIn("VirusTotal", body)
        self.assertIn("0 / 500", body)
        resp = await self.client.post(
            "/settings/virustotal/key", data={"api_key": "short"},
            allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("error=key+looks+invalid", resp.headers["Location"])
        key = "k" * 60 + "ab12"
        resp = await self.client.post(
            "/settings/virustotal/key", data={"api_key": key},
            allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("notice=key+saved", resp.headers["Location"])
        self.assertEqual(await self.db.get_setting("virustotal.api_key"),
                         key)
        body = await (await self.client.get("/settings")).text()
        self.assertIn("console", body)
        self.assertIn("••••ab12", body)
        self.assertNotIn(key, body)
        resp = await self.client.post(
            "/settings/virustotal/verify", allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("notice=key+valid", resp.headers["Location"])
        resp = await self.client.post(
            "/settings/virustotal/key/delete", allow_redirects=False)
        self.assertIn("notice=key+cleared", resp.headers["Location"])
        self.assertIsNone(await self.db.get_setting("virustotal.api_key"))
        body = await (await self.client.get("/settings")).text()
        self.assertIn("none", body)

    async def test_carto_key_settings_flow(self):
        await self.login()
        body = await (await self.client.get("/settings")).text()
        self.assertIn("Attacker map", body)
        self.assertIn("watermarked", body)
        resp = await self.client.post(
            "/settings/carto/key", data={"api_key": "has space"},
            allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("error=key+looks+invalid", resp.headers["Location"])
        key = "carto-test-key-1234"
        resp = await self.client.post(
            "/settings/carto/key", data={"api_key": key},
            allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("notice=carto+key+saved", resp.headers["Location"])
        self.assertEqual(await self.db.get_setting("carto.api_key"), key)
        body = await (await self.client.get("/settings")).text()
        self.assertIn("••••1234", body)
        self.assertNotIn(key, body)
        self.assertIn("key set", body)
        # dashboard tiles carry the key; the watermark note goes away
        await self._seed_session()
        await self.db.save_ip_intel(
            "9.9.9.9", country_code="NL", country="Netherlands")
        dash = await (await self.client.get("/")).text()
        self.assertIn(f"?api_key={key}", dash)
        self.assertNotIn("tiles watermarked", dash)
        resp = await self.client.post(
            "/settings/carto/key/delete", allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("notice=carto+key+cleared", resp.headers["Location"])
        self.assertIsNone(await self.db.get_setting("carto.api_key"))

    async def test_vt_key_verify_rejected(self):
        await self.db.set_setting("virustotal.api_key", "k" * 64)
        self.app["vt_transport"].get_responses["/files/" + "f" * 64] = (
            401, {}, {})
        await self.login()
        resp = await self.client.post(
            "/settings/virustotal/verify", allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("error=key+rejected+401", resp.headers["Location"])

    async def test_honeypot_image_settings(self):
        await self.login()
        body = await (await self.client.get("/settings")).text()
        self.assertIn("Honeypot image", body)
        self.assertIn("not pulled", body)
        resp = await self.client.post(
            "/settings/honeypot/image", data={"image": "custom:9"},
            allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("notice=", resp.headers["Location"])
        self.assertEqual(
            await self.db.get_setting("honeypot.image"), "custom:9")
        info = self.pod.inspect("carbide-ref")
        self.assertEqual(info["Config"]["Image"], "custom:9")
        body = await (await self.client.get("/settings")).text()
        self.assertIn("custom:9", body)
        self.assertIn("Clear console image", body)
        resp = await self.client.post(
            "/settings/honeypot/image/pull", allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("custom:9", self.pod.images)
        body = await (await self.client.get("/settings")).text()
        self.assertIn(">present</span>", body)
        resp = await self.client.post(
            "/settings/honeypot/image", data={"image": "has space"},
            allow_redirects=False)
        self.assertIn("error=", resp.headers["Location"])
        resp = await self.client.post(
            "/settings/honeypot/image/delete", allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIsNone(await self.db.get_setting("honeypot.image"))
        body = await (await self.client.get("/settings")).text()
        self.assertNotIn("Clear console image", body)

    async def test_forensics_prefixes_settings(self):
        await self.login()
        body = await (await self.client.get("/settings")).text()
        self.assertIn("Forensic diff exclusions", body)
        self.assertIn("defaults", body)
        resp = await self.client.post(
            "/settings/forensics/prefixes", data={"prefixes": "/a\n/b\n"},
            allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("notice=", resp.headers["Location"])
        self.assertEqual(
            await self.db.get_setting("forensics.volatile_prefixes"),
            '["/a", "/b"]')
        body = await (await self.client.get("/settings")).text()
        self.assertIn("2 prefixes · console", body)
        resp = await self.client.post(
            "/settings/forensics/prefixes", data={"prefixes": "nope"},
            allow_redirects=False)
        self.assertIn("error=", resp.headers["Location"])
        resp = await self.client.post(
            "/settings/forensics/prefixes/reset", allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIsNone(
            await self.db.get_setting("forensics.volatile_prefixes"))

    async def test_sessions_clear(self):
        await self._seed_session()
        self.assertTrue(await self.db.list_sessions())
        await self.login()
        resp = await self.client.post(
            "/settings/sessions/clear", allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("cleared+1+sessions", resp.headers["Location"])
        self.assertEqual(await self.db.list_sessions(), [])
        self.assertEqual(
            await self.db.list_squid_hits(session_id="sess1"), [])
        # Console user survives the wipe.
        self.assertIsNotNone(
            await self.db.get_web_user_by_name("admin"))

    async def test_squid_url_scan(self):
        await self._seed_session()
        await self.db.set_setting("virustotal.api_key", "k" * 64)
        await self.login()
        body = await (await self.client.get("/sessions/sess1")).text()
        self.assertIn("/actions/squid/0/scan", body)
        self.assertIn("unscanned", body)
        resp = await self.client.post("/actions/squid/0/scan")
        text = await resp.text()
        self.assertIn("submitted", text)
        row = await self.db.get_vt_url_scan("http://example.com/")
        self.assertEqual(row["status"], "pending")
        resp = await self.client.post("/actions/squid/0/scan")
        self.assertIn("awaiting verdict", await resp.text())
        await self.db.save_vt_url_scan(
            "http://example.com/", "malicious", malicious=5,
            permalink="https://www.virustotal.com/gui/url/abc")
        body = await (await self.client.get("/sessions/sess1")).text()
        self.assertIn("malicious", body)
        self.assertIn(
            'href="https://www.virustotal.com/gui/url/abc"'
            ">http://example.com/</a>", body)
        self.assertNotIn("/actions/squid/0/scan", body)
        resp = await self.client.post("/actions/squid/999/scan")
        self.assertIn("no such squid hit", await resp.text())

    async def test_file_scan_button(self):
        ref = await self._seed_session()
        await self.db.set_setting("virustotal.api_key", "k" * 64)
        await self.login()
        body = await (await self.client.get("/sessions/sess1")).text()
        self.assertIn("/actions/files/0/scan", body)
        resp = await self.client.post("/actions/files/0/scan")
        self.assertIn("submitted", await resp.text())
        row = await self.db.get_vt_scan(ref.sha256)
        self.assertEqual(row["status"], "pending")
        resp = await self.client.post("/actions/files/0/scan")
        self.assertIn("awaiting verdict", await resp.text())
        await self.db.save_vt_scan(
            ref.sha256, "malicious", malicious=7,
            permalink="https://www.virustotal.com/gui/file/abc")
        body = await (await self.client.get("/sessions/sess1")).text()
        self.assertIn(
            'href="https://www.virustotal.com/gui/file/abc"'
            ">mimikatz.exe</a>", body)
        self.assertNotIn("/actions/files/0/scan", body)
        resp = await self.client.post("/actions/files/0/scan")
        self.assertIn("already scanned: malicious", await resp.text())
        resp = await self.client.post("/actions/files/999/scan")
        self.assertIn("no such file", await resp.text())

    async def test_server_side_sorting(self):
        await self.db.ensure_session("sa", "s1", "1.1.1.1")
        await self.db.set_session_started(
            "sa", "zed", utcnow(), "1.1.1.1")
        await self.db.set_session_container("sa", "c-sa", True)
        await self.db.ensure_session("sb", "s1", "2.2.2.2")
        await self.db.set_session_started(
            "sb", "anna", utcnow(), "2.2.2.2")
        await self.db.set_session_container("sb", "c-sb", True)
        await self.login()
        body = await (await self.client.get(
            "/sessions?sort=username&dir=asc")).text()
        self.assertLess(body.index("anna"), body.index("zed"))
        self.assertIn("aria-sort=\"ascending\"", body)
        body = await (await self.client.get(
            "/sessions?sort=nope&dir=desc")).text()
        self.assertIn("aria-sort=\"descending\"", body)
        body = await (await self.client.get(
            "/attackers?sort=attacker_ip&dir=asc")).text()
        self.assertLess(body.index("1.1.1.1"), body.index("2.2.2.2"))
        body = await (await self.client.get("/attackers/1.1.1.1")).text()
        self.assertIn("data-sortable", body)

    async def test_empty_states_and_reset_modal(self):
        await self.login()
        body = await (await self.client.get("/sessions")).text()
        self.assertIn("No sessions found.", body)
        body = await (await self.client.get("/")).text()
        self.assertIn("No sessions yet.", body)
        body = await (await self.client.get("/users")).text()
        self.assertIn('id="pw-dialog"', body)
        self.assertIn("openPwDialog(this)", body)
        self.assertNotIn("prompt(", body)
        body = await (await self.client.get("/logs")).text()
        self.assertIn("Waiting for log lines", body)

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
                  "passwords": "a\nb",
                  "image_tag": "0.2.4"}, allow_redirects=False)
        self.assertEqual(resp.status, 302)
        row = await self.db.get_managed_sensor("s9")
        self.assertEqual(row["ssh_host"], "10.0.0.9")
        self.assertEqual(row["auth_passwords"], '["a", "b"]')
        self.assertEqual(row["image_tag"], "0.2.4")
        body = await (await self.client.get("/sensors/s9")).text()
        self.assertIn('name="image_tag" value="0.2.4"', body)
        self.assertIn("/actions/sensors/s9/update", body)
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


class AgoFilterTest(unittest.TestCase):
    def test_relative_buckets(self):
        from carbide.server.web.webapp import _ago_text
        now = utcnow()
        self.assertEqual(_ago_text(now), "just now")
        self.assertEqual(
            _ago_text(now - datetime.timedelta(seconds=30)), "just now")
        self.assertEqual(
            _ago_text(now - datetime.timedelta(seconds=90)), "1m ago")
        self.assertEqual(
            _ago_text(now - datetime.timedelta(minutes=59)), "59m ago")
        self.assertEqual(
            _ago_text(now - datetime.timedelta(minutes=61)), "1h ago")
        self.assertEqual(
            _ago_text(now - datetime.timedelta(hours=47)), "47h ago")
        self.assertEqual(
            _ago_text(now - datetime.timedelta(hours=48)), "2d ago")
        self.assertEqual(
            _ago_text(now - datetime.timedelta(days=30)), "30d ago")
        # non-datetimes, naive datetimes, and the future don't crash
        self.assertEqual(_ago_text(None), "")
        self.assertEqual(_ago_text("2026-10-01"), "")
        self.assertRegex(_ago_text(datetime.datetime(2026, 1, 1)),
                         r"^\d+d ago$")
        self.assertEqual(
            _ago_text(now + datetime.timedelta(minutes=5)), "just now")

    def test_epoch_sort_keys(self):
        from carbide.server.web.webapp import _epoch_filter
        at = datetime.datetime(2026, 10, 1, 1, 10, 47,
                               tzinfo=datetime.timezone.utc)
        self.assertEqual(_epoch_filter(at), str(int(at.timestamp())))
        naive = datetime.datetime(2026, 10, 1, 1, 10, 47)
        self.assertEqual(_epoch_filter(naive), str(int(at.timestamp())))
        self.assertEqual(_epoch_filter(None), "")
        self.assertEqual(_epoch_filter("2026-10-01"), "")

    def test_filter_wraps_absolute_in_title(self):
        from carbide.server.web.webapp import _ago_filter
        self.assertEqual(_ago_filter(None), "—")
        ended = utcnow() - datetime.timedelta(hours=3, minutes=5)
        self.assertEqual(
            str(_ago_filter(ended)),
            f'<span title="{ended.strftime("%Y-%m-%d %H:%M:%S")}">'
            "3h ago</span>")
