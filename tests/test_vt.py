"""Tests for carbide.server.vt (fake transport; PgCluster for the queue)."""
import datetime
import os
import tempfile
import unittest

from carbide.common.blobstore import BlobStore
from carbide.common.config import validate
from carbide.server.vt import (VTAuthError, VTClient, VTError, VTQueue,
                               VTQuotaExceeded, build_client, resolve_vt_key,
                               summarize_analysis, summarize_file,
                               summarize_url, url_id)
from tests.fakes import FakeTransport
from tests.pgcluster import PgCluster, postgres_available

from carbide.server.db import Database

requires_pg = unittest.skipUnless(postgres_available(),
                                  "postgres binaries/user missing")

FILE_BODY = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 2, "suspicious": 1,
                            "harmless": 70, "undetected": 10},
    "last_analysis_results": {
        "EngineA": {"category": "malicious", "result": "Trojan.X"},
        "EngineB": {"category": "harmless", "result": None},
        "EngineC": {"category": "suspicious", "result": "Susp.Y"},
    },
    "names": ["evil.exe"],
    "size": 1234,
}}}

ANALYSIS_ATTRS = {"status": "completed",
                  "stats": {"malicious": 0, "suspicious": 0,
                            "harmless": 65, "undetected": 5},
                  "results": {
                      "EngineA": {"category": "harmless",
                                  "result": None},
                  }}


def make_cfg(**over):
    raw = {
        "role": "server",
        "server": {"sensor_token": "tok", "db_dsn": "x",
                   "blob_dir": "y"},
        "podman": {"image": "img"},
        "virustotal": {"enabled": False, "api_key": ""},
    }
    for section, values in over.items():
        raw.setdefault(section, {}).update(values)
    return validate(raw)


def make_client(transport, quota=True, rpm=6000):
    async def claim():
        return quota() if callable(quota) else quota
    return VTClient("key", requests_per_minute=rpm, quota_claim=claim,
                    transport=transport)


class SummarizeTest(unittest.TestCase):
    def test_file_summary(self):
        out = summarize_file(FILE_BODY, "ab" * 32)
        self.assertEqual(
            (out["status"], out["malicious"], out["suspicious"],
             out["harmless"], out["undetected"]),
            ("malicious", 2, 1, 70, 10))
        self.assertEqual(out["permalink"],
                         "https://www.virustotal.com/gui/file/" + "ab" * 32)
        self.assertEqual(out["names"], ["evil.exe"])
        self.assertEqual(
            [(d["engine"], d["category"]) for d in out["detections"]],
            [("EngineA", "malicious"), ("EngineC", "suspicious")])

    def test_file_clean_and_unknown(self):
        body = {"data": {"attributes": {
            "last_analysis_stats": {"harmless": 70, "undetected": 5},
            "last_analysis_results": {}}}}
        self.assertEqual(summarize_file(body, "s")["status"], "clean")
        self.assertEqual(summarize_file({"data": {}}, "s")["status"],
                         "unknown")

    def test_analysis_summary(self):
        completed, out = True, summarize_analysis(ANALYSIS_ATTRS, "s")
        self.assertTrue(completed)
        self.assertEqual((out["status"], out["harmless"]), ("clean", 65))
        self.assertEqual(out["detections"], [])

    def test_url_id_and_summary(self):
        self.assertEqual(url_id("http://x/"), "aHR0cDovL3gv")
        self.assertNotIn("=", url_id("http://example.com/"))
        out = summarize_url(FILE_BODY, "http://x/evil.exe")
        self.assertEqual((out["status"], out["malicious"]), ("malicious", 2))
        self.assertEqual(
            out["permalink"],
            "https://www.virustotal.com/gui/url/"
            + url_id("http://x/evil.exe"))
        self.assertEqual(out["url"], "http://x/evil.exe")


class ClientTest(unittest.IsolatedAsyncioTestCase):
    async def test_lookup_hit_and_miss(self):
        transport = FakeTransport()
        transport.get_responses["/files/abc"] = (200, FILE_BODY, {})
        client = make_client(transport)
        out = await client.lookup("abc")
        self.assertEqual(out["status"], "malicious")
        self.assertIsNone(await client.lookup("missing"))

    async def test_url_lookup_and_submit(self):
        transport = FakeTransport()
        transport.get_responses["/urls/" + url_id("http://k/")] = (
            200, FILE_BODY, {})
        client = make_client(transport)
        out = await client.lookup_url("http://k/")
        self.assertEqual(out["status"], "malicious")
        self.assertIn("/gui/url/", out["permalink"])
        self.assertIsNone(await client.lookup_url("http://new/"))
        analysis_id = await client.submit_url("http://new/")
        self.assertEqual(analysis_id, "an-url-1")
        self.assertIn(("FORM", "/urls", {"url": "http://new/"}),
                      transport.calls)

    async def test_lookup_auth_error(self):
        transport = FakeTransport()
        transport.get_responses["/files/abc"] = (401, {}, {})
        with self.assertRaises(VTAuthError):
            await make_client(transport).lookup("abc")

    async def test_upload_returns_id(self):
        client = make_client(FakeTransport())
        self.assertEqual(await client.upload(b"xx", "ee"), "an-1")

    async def test_poll_queued_then_completed(self):
        transport = FakeTransport()
        transport.get_responses["/analyses/an-1"] = (
            200, {"data": {"attributes": {"status": "queued"}}}, {})
        client = make_client(transport)
        completed, summary = await client.poll_analysis("an-1", "s")
        self.assertEqual((completed, summary), (False, None))
        transport.get_responses["/analyses/an-1"] = (
            200, {"data": {"attributes": dict(ANALYSIS_ATTRS)}}, {})
        completed, summary = await client.poll_analysis("an-1", "s")
        self.assertTrue(completed)
        self.assertEqual(summary["status"], "clean")

    async def test_rate_limit_retries_then_raises(self):
        transport = FakeTransport()
        transport.get_responses["/files/abc"] = (
            429, {}, {"Retry-After": "0"})
        client = make_client(transport)
        with self.assertRaises(VTError):
            await client.lookup("abc")
        gets = [c for c in transport.calls if c[0] == "GET"]
        self.assertEqual(len(gets), 4)  # 1 + 3 retries

    async def test_quota_exhausted_blocks_calls(self):
        transport = FakeTransport()
        with self.assertRaises(VTQuotaExceeded):
            await make_client(transport, quota=False).lookup("abc")
        self.assertEqual(transport.calls, [])

    async def test_pacer_spaces_requests(self):
        import time
        transport = FakeTransport()
        client = make_client(transport, rpm=60)  # 1s spacing
        start = time.monotonic()
        await client.lookup("a")
        await client.lookup("b")
        self.assertGreaterEqual(time.monotonic() - start, 0.9)


class FakeClient:
    def __init__(self):
        self.lookups = {}
        self.lookup_error = None
        self.uploads = []
        self.analysis_id = "an-1"
        self.polls = {}

    async def lookup(self, sha):
        if self.lookup_error is not None:
            raise self.lookup_error
        return self.lookups.get(sha)

    async def upload(self, data, filename):
        self.uploads.append((len(data), filename))
        return self.analysis_id

    async def lookup_url(self, url):
        return self.lookups.get("url:" + url)

    async def submit_url(self, url):
        self.uploads.append((0, url))
        return self.analysis_id

    async def poll_analysis(self, analysis_id, sha, permalink=""):
        return self.polls.get(analysis_id, (False, None))


@requires_pg
class QueueTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import asyncio
        loop = asyncio.get_running_loop()
        self.cluster = PgCluster()
        dsn = await loop.run_in_executor(None, self.cluster.start)
        self.db = Database(dsn)
        await self.db.connect()
        self.tmp = tempfile.TemporaryDirectory()
        self.blobs = BlobStore(os.path.join(self.tmp.name, "blobs"), 10**9)
        self.client = FakeClient()
        self.queue = VTQueue(self.db, self.blobs, make_cfg(),
                             client=self.client)

    async def asyncTearDown(self):
        import asyncio
        await self.db.close()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.cluster.stop)
        self.tmp.cleanup()

    async def _capture(self, ref, name="up/x", origin="sensor"):
        await self.db.ensure_session("s", "s1", "9.9.9.9")
        await self.db.add_blob(ref.sha256, ref.path, ref.size)
        await self.db.add_session_file(
            "s", name, ref.sha256, ref.size,
            datetime.datetime.now(datetime.timezone.utc), origin=origin)

    async def test_known_file_saved_without_upload(self):
        ref = self.blobs.put_bytes(b"evil")
        await self._capture(ref)
        self.client.lookups[ref.sha256] = {
            "status": "malicious", "malicious": 9, "suspicious": 0,
            "harmless": 60, "undetected": 5, "permalink": "https://vt/g",
            "detections": []}
        self.assertEqual(await self.queue.run_once(), 1)
        row = await self.db.get_vt_scan(ref.sha256)
        self.assertEqual((row["status"], row["malicious"]),
                         ("malicious", 9))
        self.assertEqual(self.client.uploads, [])
        # second pass: nothing due
        self.assertEqual(await self.queue.run_once(), 0)

    async def test_unknown_file_uploaded_then_polled(self):
        ref = self.blobs.put_bytes(b"brand-new")
        await self._capture(ref)
        self.assertEqual(await self.queue.run_once(), 1)
        row = await self.db.get_vt_scan(ref.sha256)
        self.assertEqual((row["status"], row["analysis_id"]),
                         ("pending", "an-1"))
        self.assertEqual(len(self.client.uploads), 1)
        # still queued: stays pending, no re-upload
        self.assertEqual(await self.queue.run_once(), 1)
        self.assertEqual(len(self.client.uploads), 1)
        self.client.polls["an-1"] = (True, {
            "status": "clean", "malicious": 0, "suspicious": 0,
            "harmless": 70, "undetected": 3, "permalink": "https://vt/g2",
            "detections": []})
        self.assertEqual(await self.queue.run_once(), 1)
        row = await self.db.get_vt_scan(ref.sha256)
        self.assertEqual((row["status"], row["harmless"]), ("clean", 70))
        self.assertEqual(len(self.client.uploads), 1)

    async def test_forensics_files_never_scanned(self):
        sensor_ref = self.blobs.put_bytes(b"attacker-upload")
        await self._capture(sensor_ref, name="scp-upload:/tmp/x")
        foren_ref = self.blobs.put_bytes(b"passwd-contents")
        await self._capture(foren_ref, name="container:/etc/passwd",
                            origin="forensics")
        self.assertEqual(await self.queue.run_once(), 1)
        self.assertIsNotNone(
            await self.db.get_vt_scan(sensor_ref.sha256))
        self.assertIsNone(await self.db.get_vt_scan(foren_ref.sha256))
        self.assertEqual(len(self.client.uploads), 1)

    async def test_scan_url_submit_then_poll(self):
        row = await self.queue.scan_url("http://evil/x")
        self.assertEqual(row["status"], "pending")
        self.assertEqual(len(self.client.uploads), 1)
        # Worker pass re-polls the pending URL (no file candidates here).
        self.assertEqual(await self.queue.run_once(), 1)
        self.client.polls["an-1"] = (True, {
            "status": "malicious", "malicious": 4, "suspicious": 0,
            "harmless": 60, "undetected": 5,
            "permalink": "https://www.virustotal.com/gui/url/abc",
            "detections": []})
        self.assertEqual(await self.queue.run_once(), 1)
        row = await self.db.get_vt_url_scan("http://evil/x")
        self.assertEqual((row["status"], row["malicious"]),
                         ("malicious", 4))
        self.assertEqual(len(self.client.uploads), 1)
        self.assertEqual(await self.queue.run_once(), 0)

    async def test_oversize_and_missing_blob(self):
        big = "b" * 64
        gone = "c" * 64
        await self.db.ensure_session("s", "s1", "9.9.9.9")
        at = datetime.datetime.now(datetime.timezone.utc)
        await self.db.add_session_file("s", "up/big", big,
                                       64 * 1024 * 1024, at)
        await self.db.add_session_file("s", "up/gone", gone, 3, at)
        await self.db.add_blob("f" * 64, "/blobs/ff", 5)
        self.assertEqual(await self.queue.run_once(), 2)
        self.assertIsNone(await self.db.get_vt_scan("f" * 64))
        skipped = await self.db.get_vt_scan(big)
        self.assertEqual(skipped["status"], "skipped")
        self.assertIn("exceeds", skipped["error"])
        error = await self.db.get_vt_scan(gone)
        self.assertEqual(error["status"], "error")
        self.assertIn("unreadable", error["error"])
        self.assertEqual(self.client.uploads, [])

    async def test_quota_and_auth_stop_pass(self):
        ref = self.blobs.put_bytes(b"q")
        await self._capture(ref)
        self.client.lookup_error = VTQuotaExceeded("cap")
        self.assertEqual(await self.queue.run_once(), 0)
        self.assertIsNone(await self.db.get_vt_scan(ref.sha256))
        self.client.lookup_error = VTAuthError("401")
        self.assertEqual(await self.queue.run_once(), 0)
        self.assertIsNone(await self.db.get_vt_scan(ref.sha256))

    async def test_resolve_key_prefers_setting(self):
        cfg = make_cfg(virustotal={"enabled": True, "api_key": "file-key"})
        self.assertEqual(await resolve_vt_key(self.db, cfg), "file-key")
        await self.db.set_setting("virustotal.api_key", "  db-key\n")
        self.assertEqual(await resolve_vt_key(self.db, cfg), "db-key")
        await self.db.delete_setting("virustotal.api_key")
        self.assertEqual(await resolve_vt_key(self.db, cfg), "file-key")
        self.assertEqual(await resolve_vt_key(self.db, make_cfg()), "")

    async def test_queue_idles_without_key(self):
        ref = self.blobs.put_bytes(b"nokey")
        await self._capture(ref)
        queue = VTQueue(self.db, self.blobs, make_cfg())
        self.assertEqual(await queue.run_once(), 0)
        self.assertIsNone(await self.db.get_vt_scan(ref.sha256))

    async def test_build_client_claims_quota(self):
        cfg = make_cfg(virustotal={"enabled": True, "api_key": "k",
                                   "daily_cap": 1})
        transport = FakeTransport()
        transport.get_responses["/files/abc"] = (200, FILE_BODY, {})
        client = build_client(cfg, self.db, transport=transport)
        client._interval = 0
        out = await client.lookup("abc")
        self.assertEqual(out["status"], "malicious")
        with self.assertRaises(VTQuotaExceeded):
            await client.lookup("abc")


if __name__ == "__main__":
    unittest.main()
