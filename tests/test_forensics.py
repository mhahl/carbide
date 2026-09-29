import os
import tempfile
import unittest

from carbide.common.blobstore import BlobStore
from carbide.common.config import validate
from carbide.server.forensics import (
    Forensics, is_text, normalize_changes, unified_diff_text,
)
from tests.fakes import FakeDatabase, FakePodman


def make_config(**over):
    raw = {
        "role": "server",
        "server": {"sensor_token": "tok", "db_dsn": "x",
                   "blob_dir": "y"},
        "podman": {"image": "img"},
        "affinity": {"snapshot_retention": 2},
        "forensics": {"max_file_bytes": 100},
    }
    for section, values in over.items():
        raw.setdefault(section, {}).update(values)
    return validate(raw)


class NormalizeTest(unittest.TestCase):
    def test_docker_ints(self):
        rows, warnings = normalize_changes([
            {"Path": "/a", "Kind": 1}, {"Path": "/b", "Kind": 2},
            {"Path": "/c", "Kind": 0}])
        self.assertEqual(warnings, [])
        self.assertEqual(rows, [("/a", "added"), ("/b", "deleted"),
                                ("/c", "changed")])

    def test_podman_letters(self):
        rows, warnings = normalize_changes([
            {"Path": "/a", "Kind": "A"}, {"Path": "/d", "Kind": "D"},
            {"Path": "/c", "Kind": "C"}])
        self.assertEqual(warnings, [])
        self.assertEqual(rows, [("/a", "added"), ("/c", "changed"),
                                ("/d", "deleted")])

    def test_unknown_kind_warns(self):
        rows, warnings = normalize_changes([{"Path": "/x", "Kind": 9}])
        self.assertEqual(rows, [("/x", "changed")])
        self.assertEqual(len(warnings), 1)

    def test_garbage_entry_warns(self):
        rows, warnings = normalize_changes([{"nope": 1}])
        self.assertEqual(rows, [])
        self.assertEqual(len(warnings), 1)

    def test_text_and_diff(self):
        self.assertTrue(is_text(b"hello\n"))
        self.assertFalse(is_text(b"a\x00b"))
        diff = unified_diff_text(b"a\n", b"a\nb\n", "/f")
        self.assertIn("+b", diff)
        self.assertIsNone(unified_diff_text(b"a\x00", b"b", "/f"))


class FakePool:
    def __init__(self, pod):
        self._pod = pod

    async def run_sync(self, fn, *a, **k):
        return fn(*a, **k)

    def reference_id(self):
        return "carbide-ref"


class ForensicsTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = FakeDatabase()
        self.pod = FakePodman()
        cid = self.pod.create_container("c", "img", "u", 1, "", {}, 1, 1)
        self.cid = cid
        self.ref = self.pod.create_container("carbide-ref", "img", "u", 2,
                                             "", {}, 1, 1)
        blobs = BlobStore(os.path.join(self.tmp.name, "blobs"), 10**9)
        self.forensics = Forensics(FakePool(self.pod), self.pod, self.db,
                                   blobs, make_config())

    async def test_collect_happy_path(self):
        self.pod.write_file(self.cid, "/etc/motd", b"pwned\n")
        self.pod.write_file(self.cid, "/tmp/tool", b"evil")
        self.pod.delete_file(self.cid, "/home/honey/.profile")
        summary = await self.forensics.collect(
            sensor_id="s1", attacker_ip="1.2.3.4", session_id="sess",
            container_id=self.cid, reason="test")
        self.assertEqual(summary["changes"], 3)
        rows = await self.db.get_diff_rows("sess")
        self.assertEqual(rows, [("/etc/motd", "changed"),
                                ("/home/honey/.profile", "deleted"),
                                ("/tmp/tool", "added")])
        md, js = await self.db.get_report("sess")
        self.assertIn("[C] /etc/motd", md)
        self.assertIn("[A] /tmp/tool", md)
        self.assertIn("[D] /home/honey/.profile", md)
        self.assertIn("+pwned", md)
        self.assertIn('"kind": "added"', js)
        # added file stored as blob
        names = [f[1] for f in self.db.files]
        self.assertIn("container:/tmp/tool", names)
        # snapshot committed
        self.assertEqual(len(self.pod.images), 1)
        snaps = await self.db.list_snapshots("s1", "1.2.3.4")
        self.assertEqual(len(snaps), 1)

    async def test_snapshot_tag_is_valid_reference(self):
        # Registry references must be lowercase with no dots that could
        # parse as a domain — even for mixed-case sensor ids and dotted IPs.
        import re
        await self.forensics.collect(
            sensor_id="S1-Mixed", attacker_ip="10.89.1.1",
            session_id="s", container_id=self.cid)
        self.assertEqual(len(self.pod.images), 1)
        tag = self.pod.images[0]
        self.assertRegex(tag, r"^[a-z0-9][a-z0-9_-]*$")
        self.assertIn("s1-mixed", tag)
        self.assertIn("10_89_1_1", tag)

    async def test_snapshot_retention_prunes(self):
        for _ in range(4):
            await self.forensics.collect(
                sensor_id="s1", attacker_ip="1.2.3.4",
                session_id="s", container_id=self.cid)
        snaps = await self.db.list_snapshots("s1", "1.2.3.4")
        self.assertEqual(len(snaps), 2)
        self.assertEqual(len(self.pod.images), 2)

    async def test_oversized_and_binary(self):
        self.pod.write_file(self.cid, "/big", b"x" * 101)
        self.pod.write_file(self.cid, "/bin", b"\x00\x01\x02")
        await self.forensics.collect(
            sensor_id="s1", attacker_ip="1.2.3.4", session_id="s",
            container_id=self.cid)
        md, _js = await self.db.get_report("s")
        self.assertIn("oversized", md)
        self.assertIn("binary", md)
        names = [f[1] for f in self.db.files]
        self.assertNotIn("container:/big", names)
        self.assertIn("container:/bin", names)

    async def test_directory_skipped(self):
        summary = await self.forensics.collect(
            sensor_id="s1", attacker_ip="1.2.3.4", session_id="s",
            container_id=self.cid)
        self.assertEqual(summary["changes"], 0)

    async def test_diff_failure_reports_unavailable(self):
        self.pod.remove(self.cid)
        summary = await self.forensics.collect(
            sensor_id="s1", attacker_ip="1.2.3.4", session_id="s",
            container_id=self.cid)
        self.assertEqual(summary["changes"], 0)
        self.assertTrue(summary["warnings"])
        md, _js = await self.db.get_report("s")
        self.assertIn("diff failed", md)

    async def test_quota_exceeded_noted(self):
        blobs = BlobStore(os.path.join(self.tmp.name, "tiny"), 1)
        self.forensics._blobs = blobs
        self.pod.write_file(self.cid, "/tmp/tool", b"evil")
        await self.forensics.collect(
            sensor_id="s1", attacker_ip="1.2.3.4", session_id="s",
            container_id=self.cid)
        md, _js = await self.db.get_report("s")
        self.assertIn("quota", md)

    async def test_blob_failure_still_saves_partial_report(self):
        # A blob-store error (disk full, missing mount) on one file must
        # degrade to a warning, never to a missing report.
        class BrokenBlobs:
            def put_bytes(self, data):
                raise OSError("disk full")
        self.forensics._blobs = BrokenBlobs()
        self.pod.write_file(self.cid, "/tmp/tool", b"evil")
        summary = await self.forensics.collect(
            sensor_id="s1", attacker_ip="1.2.3.4", session_id="s",
            container_id=self.cid)
        self.assertTrue(summary["warnings"])
        md, _js = await self.db.get_report("s")
        self.assertIn("/tmp/tool", md)
        self.assertIn("disk full", md)

    async def test_session_file_db_failure_still_saves_report(self):
        class BrokenFiles(FakeDatabase):
            async def add_session_file(self, *a, **k):
                raise RuntimeError("db gone")
        self.forensics._db = BrokenFiles()
        self.pod.write_file(self.cid, "/tmp/tool", b"evil")
        summary = await self.forensics.collect(
            sensor_id="s1", attacker_ip="1.2.3.4", session_id="s",
            container_id=self.cid)
        self.assertTrue(summary["warnings"])
        md, _js = await self.forensics._db.get_report("s")
        self.assertIn("/tmp/tool", md)

    async def test_unusable_diff_payload_reports_unavailable(self):
        self.pod.diff = lambda cid: 42
        summary = await self.forensics.collect(
            sensor_id="s1", attacker_ip="1.2.3.4", session_id="s",
            container_id=self.cid)
        self.assertEqual(summary["changes"], 0)
        self.assertTrue(summary["warnings"])
        md, _js = await self.db.get_report("s")
        self.assertIn("diff", md)


if __name__ == "__main__":
    unittest.main()
