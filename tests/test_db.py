"""Postgres-backed tests for carbide.server.db (throwaway cluster)."""
import datetime
import unittest

from tests.pgcluster import PgCluster, postgres_available

from carbide.server.db import Database, DatabaseClosedError

requires_pg = unittest.skipUnless(postgres_available(),
                                  "postgres binaries/user missing")


def now():
    return datetime.datetime.now(datetime.timezone.utc)


@requires_pg
class DbTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.cluster = PgCluster()
        dsn = await asyncio_wrap(self.cluster.start)
        self.db = Database(dsn)
        await self.db.connect()

    async def asyncTearDown(self):
        await self.db.close()
        await asyncio_wrap(self.cluster.stop)

    async def test_migrate_idempotent(self):
        await self.db.migrate()
        await self.db.migrate()

    async def test_affinity_crud(self):
        self.assertIsNone(await self.db.get_affinity("s1", "1.2.3.4"))
        await self.db.set_affinity("s1", "1.2.3.4", "c1", 22001, "pw",
                                   "10.0.0.2")
        aff = await self.db.get_affinity("s1", "1.2.3.4")
        self.assertEqual(aff["container_id"], "c1")
        self.assertEqual(aff["ssh_port"], 22001)
        self.assertFalse(aff["has_activity"])
        by_ip = await self.db.get_affinity_by_container_ip("10.0.0.2")
        self.assertEqual(by_ip["attacker_ip"], "1.2.3.4")
        self.assertEqual(await self.db.ports_in_use(), {22001})
        await self.db.set_affinity_activity("s1", "1.2.3.4", True)
        aff = await self.db.get_affinity("s1", "1.2.3.4")
        self.assertTrue(aff["has_activity"])
        await self.db.touch_affinity_end("s1", "1.2.3.4")
        aff = await self.db.get_affinity("s1", "1.2.3.4")
        self.assertIsNotNone(aff["last_session_end"])
        self.assertEqual(len(await self.db.list_affinities()), 1)
        await self.db.delete_affinity("s1", "1.2.3.4")
        self.assertIsNone(await self.db.get_affinity("s1", "1.2.3.4"))

    async def test_session_flow(self):
        await self.db.ensure_session("sess", "s1", "9.9.9.9")
        await self.db.ensure_session("sess", "s1", "9.9.9.9")
        await self.db.set_session_started("sess", "root", now(), "9.9.9.9")
        await self.db.set_session_container("sess", "c9", True)
        row = await self.db.latest_open_session("s1", "9.9.9.9")
        self.assertEqual(row[0], "sess")
        self.assertFalse(await self.db.session_has_content("sess"))
        await self.db.add_auth_attempt("sess", "s1", "root", "pw", True,
                                       True, now())
        await self.db.add_transcript("sess", "ch1", "in", "stdin", 0,
                                     b"hello", now())
        self.assertTrue(await self.db.session_has_content("sess"))
        self.assertEqual(await self.db.session_byte_count("sess"), 5)
        await self.db.set_session_end("sess", now(), "eof")
        self.assertIsNone(await self.db.latest_open_session("s1", "9.9.9.9"))
        row = await self.db.latest_session("s1", "9.9.9.9")
        self.assertEqual(row[0], "sess")
        session = await self.db.get_session("sess")
        self.assertEqual(session[3], "root")
        await self.db.set_session_over_quota("sess")
        session = await self.db.get_session("sess")
        self.assertTrue(session[6])

    async def test_blobs_files_diffs_reports(self):
        await self.db.ensure_session("s", "s1", "1.1.1.1")
        await self.db.add_blob("a" * 64, "/blobs/aa", 3)
        await self.db.add_blob("a" * 64, "/blobs/aa", 3)
        self.assertIsNotNone(await self.db.get_blob("a" * 64))
        await self.db.add_session_file("s", "up/x", "a" * 64, 3, now())
        await self.db.add_diff_rows("s", [("/a", "added")])
        self.assertEqual(await self.db.get_diff_rows("s"),
                         [("/a", "added")])
        await self.db.save_report("s", "# md", '{"a":1}', now())
        await self.db.save_report("s", "# md2", '{"a":2}', now())
        md, js = await self.db.get_report("s")
        self.assertEqual(md, "# md2")

    async def test_claim_record(self):
        self.assertTrue(await self.db.claim_record("r1"))
        self.assertFalse(await self.db.claim_record("r1"))

    async def test_snapshots_and_squid(self):
        await self.db.add_snapshot("s1", "1.1.1.1", "c1", "img:1")
        await self.db.add_snapshot("s1", "1.1.1.1", "c1", "img:2")
        snaps = await self.db.list_snapshots("s1", "1.1.1.1")
        self.assertEqual([s[0] for s in snaps], ["img:1", "img:2"])
        await self.db.delete_snapshot("img:1")
        snaps = await self.db.list_snapshots("s1", "1.1.1.1")
        self.assertEqual([s[0] for s in snaps], ["img:2"])
        await self.db.add_squid_hit("s", "s1", "10.0.0.2", now(), "GET",
                                    "http://x/", 200, 10, "text/html")

    async def test_close_is_idempotent_and_guards_queries(self):
        await self.db.close()
        await self.db.close()
        with self.assertRaises(DatabaseClosedError):
            await self.db._exec("SELECT 1")
        with self.assertRaises(DatabaseClosedError):
            await self.db.claim_record("r1")
        with self.assertRaises(DatabaseClosedError):
            await self.db.migrate()
        # reconnect clears the closed flag
        await self.db.connect()
        self.assertIsNone(await self.db.get_affinity("s1", "9.9.9.9"))


def asyncio_wrap(fn):
    import asyncio
    loop = asyncio.get_running_loop()
    return loop.run_in_executor(None, fn)


if __name__ == "__main__":
    unittest.main()
