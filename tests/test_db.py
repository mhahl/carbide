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

    async def test_web_users_and_sessions(self):
        uid = await self.db.create_web_user("op", "hash1")
        user = await self.db.get_web_user_by_name("op")
        self.assertEqual(user["id"], uid)
        self.assertFalse(user["disabled"])
        self.assertEqual(
            [u["username"] for u in await self.db.list_web_users()],
            ["op"])
        await self.db.set_web_user_password(uid, "hash2")
        self.assertEqual(
            (await self.db.get_web_user(uid))["pw_hash"], "hash2")
        future = now() + datetime.timedelta(hours=1)
        await self.db.create_web_session("sha1", uid, future)
        row = await self.db.get_web_session("sha1")
        self.assertEqual(row[1], uid)
        self.assertEqual(row[3], "op")
        await self.db.set_web_user_disabled(uid, True)
        self.assertTrue((await self.db.get_web_user(uid))["disabled"])
        past = now() - datetime.timedelta(hours=1)
        await self.db.create_web_session("sha-old", uid, past)
        await self.db.delete_expired_web_sessions()
        self.assertIsNone(await self.db.get_web_session("sha-old"))
        self.assertIsNotNone(await self.db.get_web_session("sha1"))
        await self.db.delete_web_session("sha1")
        self.assertIsNone(await self.db.get_web_session("sha1"))

    async def test_managed_sensors(self):
        self.assertIsNone(
            await self.db.get_managed_sensor("s9"))
        await self.db.upsert_managed_sensor(
            "s9", "10.0.0.9", auth_passwords='["a"]')
        row = await self.db.get_managed_sensor("s9")
        self.assertEqual(row["ssh_host"], "10.0.0.9")
        self.assertEqual(row["auth_passwords"], '["a"]')
        await self.db.upsert_managed_sensor(
            "s9", "10.0.0.10", listen_port=2223)
        row = await self.db.get_managed_sensor("s9")
        self.assertEqual(row["ssh_host"], "10.0.0.10")
        self.assertEqual(row["listen_port"], 2223)
        self.assertEqual(
            [m["sensor_id"]
             for m in await self.db.list_managed_sensors()], ["s9"])
        await self.db.delete_managed_sensor("s9")
        self.assertEqual(await self.db.list_managed_sensors(), [])

    async def test_console_reads(self):
        await self.db.note_sensor("s1")
        await self.db.ensure_session("a", "s1", "1.1.1.1")
        await self.db.set_session_started("a", "root", now(), "1.1.1.1")
        await self.db.ensure_session("b", "s1", "2.2.2.2")
        await self.db.set_session_started("b", "u", now(), "2.2.2.2")
        await self.db.set_session_end("b", now(), "done")
        await self.db.add_auth_attempt("a", "s1", "root", "pw", True,
                                       True, now())
        await self.db.add_transcript("a", "ch", "in", "pty", 0,
                                     b"x", now())
        await self.db.add_session_file("a", "f", None, 3, now())
        await self.db.add_squid_hit("a", "s1", "10.0.0.2", now(), "GET",
                                    "http://x/", 200, 5, "text/html")
        await self.db.add_snapshot("s1", "1.1.1.1", "c1", "img:9")
        self.assertEqual(len(await self.db.list_sensors()), 1)
        self.assertEqual(len(await self.db.list_sessions()), 2)
        self.assertEqual(
            len(await self.db.list_sessions(open_only=True)), 1)
        self.assertEqual(
            len(await self.db.list_sessions(ip="2.2.2.2")), 1)
        await self.db.set_session_container("a", "c1", True)
        self.assertEqual(
            len(await self.db.list_sessions(require_container=True)), 1)
        self.assertEqual(len(await self.db.get_transcript("a")), 1)
        self.assertEqual(len(await self.db.list_session_files("a")), 1)
        self.assertEqual(
            len(await self.db.list_auth_attempts(username="root")), 1)
        self.assertEqual(
            len(await self.db.list_auth_attempts(accepted=False)), 0)
        self.assertEqual(
            len(await self.db.list_squid_hits(session_id="a")), 1)
        self.assertEqual(
            len(await self.db.list_snapshots_all(sensor_id="s1")), 1)
        self.assertEqual(await self.db.count_open_sessions(), 1)
        self.assertEqual(
            await self.db.count_sessions_since(
                now() - datetime.timedelta(hours=1)), 2)
        self.assertEqual(await self.db.count_affinities(), 0)
        self.assertEqual(
            await self.db.count_auth_since(
                now() - datetime.timedelta(hours=1)), 1)

    async def test_reset_wipes_all_data(self):
        await self.db.set_affinity("s1", "1.2.3.4", "c1", 22001, "pw",
                                   "10.0.0.2")
        await self.db.ensure_session("sess", "s1", "1.2.3.4")
        await self.db.add_auth_attempt("sess", "s1", "root", "pw", True,
                                       True, now())
        await self.db.add_transcript("sess", "ch1", "in", "stdin", 0,
                                     b"hello", now())
        await self.db.add_blob("b" * 64, "/blobs/bb", 3)
        await self.db.save_report("sess", "# md", "{}", now())
        self.assertTrue(await self.db.claim_record("r1"))
        uid = await self.db.create_web_user("op", "hash1")
        await self.db.create_web_session(
            "sha1", uid, now() + datetime.timedelta(hours=1))
        await self.db.upsert_managed_sensor("s9", "10.0.0.9")

        tables = await self.db.reset()

        self.assertIn("sessions", tables)
        self.assertIn("web_users", tables)
        self.assertNotIn("schema_version", tables)
        self.assertIsNone(await self.db.get_session("sess"))
        self.assertIsNone(await self.db.get_affinity("s1", "1.2.3.4"))
        self.assertEqual(await self.db.list_auth_attempts(), [])
        self.assertEqual(await self.db.get_transcript("sess"), [])
        self.assertIsNone(await self.db.get_blob("b" * 64))
        self.assertIsNone(await self.db.get_report("sess"))
        self.assertTrue(await self.db.claim_record("r1"))
        self.assertIsNone(await self.db.get_web_user_by_name("op"))
        self.assertIsNone(await self.db.get_managed_sensor("s9"))
        # schema_version survives; sequences restart; db stays usable
        versions = await self.db._exec(
            "SELECT version FROM schema_version", fetch="all")
        self.assertEqual({row[0] for row in versions}, {1, 2, 3, 4})
        self.assertEqual(await self.db.create_web_user("op2", "h"), 1)
        await self.db.migrate()

    async def test_vt_scans_crud_and_candidates(self):
        self.assertIsNone(await self.db.get_vt_scan("c" * 64))
        await self.db.ensure_session("s", "s1", "9.9.9.9")
        await self.db.add_session_file("s", "up/c", "c" * 64, 3, now())
        await self.db.add_session_file("s", "up/d", "d" * 64, 4, now())
        await self.db.add_session_file("s", "dropped", "", 0, now())
        await self.db.add_blob("f" * 64, "/blobs/ff", 5)
        cutoff = now() - datetime.timedelta(days=30)
        cands = await self.db.vt_candidates(10, cutoff)
        # session files only: dropped (empty sha) and forensic-only
        # blobs are never candidates
        self.assertEqual({sha for sha, _size in cands},
                         {"c" * 64, "d" * 64})
        await self.db.save_vt_scan("c" * 64, "malicious", malicious=5,
                                   harmless=70, permalink="https://vt/x",
                                   report_json='{"a":1}')
        scan = await self.db.get_vt_scan("c" * 64)
        self.assertEqual(scan["status"], "malicious")
        self.assertEqual(scan["malicious"], 5)
        self.assertEqual(scan["permalink"], "https://vt/x")
        cands = await self.db.vt_candidates(10, cutoff)
        self.assertEqual([sha for sha, _size in cands], ["d" * 64])
        # a fresh scan is not due; an old cutoff makes it due again
        fresh = await self.db.vt_candidates(
            10, now() + datetime.timedelta(days=1))
        self.assertEqual({sha for sha, _size in fresh},
                         {"c" * 64, "d" * 64})
        # pending analyses stay due regardless of cutoff
        await self.db.save_vt_scan("d" * 64, "pending",
                                   analysis_id="an-1")
        due = await self.db.vt_candidates(10, cutoff)
        self.assertEqual([sha for sha, _size in due], ["d" * 64])
        self.assertEqual(
            (await self.db.get_vt_scan("d" * 64))["analysis_id"], "an-1")

    async def test_vt_quota_claim(self):
        day = now().date()
        self.assertEqual(await self.db.vt_quota_used(day), 0)
        self.assertTrue(await self.db.claim_vt_quota(day, 2))
        self.assertTrue(await self.db.claim_vt_quota(day, 2))
        self.assertFalse(await self.db.claim_vt_quota(day, 2))
        self.assertEqual(await self.db.vt_quota_used(day), 2)
        self.assertTrue(await self.db.claim_vt_quota(
            day + datetime.timedelta(days=1), 2))

    async def test_ip_intel_crud_and_due_scans(self):
        await self.db.ensure_session("s1", "s1", "1.2.3.4")
        await self.db.ensure_session("s2", "s1", "5.6.7.8")
        self.assertIsNone(await self.db.get_ip_intel("1.2.3.4"))
        cutoff = now() - datetime.timedelta(days=7)
        self.assertEqual(set(await self.db.ips_needing_scan(10, cutoff)),
                         {"1.2.3.4", "5.6.7.8"})
        await self.db.save_ip_intel("1.2.3.4", rdns="x.example",
                                    open_ports='[{"port": 22}]')
        intel = await self.db.get_ip_intel("1.2.3.4")
        self.assertEqual(intel["status"], "ok")
        self.assertEqual(intel["rdns"], "x.example")
        self.assertEqual(await self.db.ips_needing_scan(10, cutoff),
                         ["5.6.7.8"])

    async def test_attacker_overview_queries(self):
        await self.db.ensure_session("a", "s1", "9.9.9.9")
        await self.db.set_session_started("a", "root", now(), "9.9.9.9")
        await self.db.ensure_session("b", "s1", "9.9.9.9")
        await self.db.add_blob("e" * 64, "/blobs/ee", 3)
        await self.db.add_session_file("a", "up/x", "e" * 64, 3, now())
        await self.db.save_vt_scan("e" * 64, "malicious", malicious=9)
        await self.db.save_ip_intel("9.9.9.9")
        rows = await self.db.list_attackers()
        self.assertEqual(len(rows), 1)
        ip, sessions, _seen, files, malicious, intel = rows[0]
        self.assertEqual(
            (ip, sessions, files, malicious, intel),
            ("9.9.9.9", 2, 1, 1, "ok"))
        frows = await self.db.list_files_by_ip("9.9.9.9")
        self.assertEqual(len(frows), 1)
        self.assertEqual(frows[0][2:], ("up/x", "e" * 64, 3, frows[0][5],
                                        "malicious", 9, 0, ""))
        self.assertEqual(await self.db.list_files_by_ip("8.8.8.8"), [])

    async def test_list_sorting(self):
        t0 = now()
        await self.db.ensure_session("sa", "s1", "1.1.1.1")
        await self.db.set_session_started("sa", "zed", t0, "1.1.1.1")
        await self.db.ensure_session("sb", "s1", "2.2.2.2")
        await self.db.set_session_started(
            "sb", "anna", t0 + datetime.timedelta(seconds=10), "2.2.2.2")
        await self.db.set_session_end("sb", t0, "closed")
        by_user = await self.db.list_sessions(sort="username",
                                              descending=False)
        self.assertEqual([r[0] for r in by_user], ["sb", "sa"])
        by_user_desc = await self.db.list_sessions(sort="username",
                                                   descending=True)
        self.assertEqual([r[0] for r in by_user_desc], ["sa", "sb"])
        # invalid sort falls back to started_at desc (injection-safe:
        # only allowlist columns ever reach ORDER BY)
        fallback = await self.db.list_sessions(
            sort="1; DROP TABLE sessions", descending=True)
        self.assertEqual([r[0] for r in fallback], ["sb", "sa"])
        # open sessions (NULL ended_at) sort last in both directions
        ended_asc = await self.db.list_sessions(sort="ended_at",
                                                descending=False)
        self.assertEqual([r[0] for r in ended_asc], ["sb", "sa"])
        ended_desc = await self.db.list_sessions(sort="ended_at",
                                                 descending=True)
        self.assertEqual([r[0] for r in ended_desc], ["sb", "sa"])
        # attempts + attackers
        await self.db.add_auth_attempt("sa", "s1", "zed", "pw", True,
                                       False, t0)
        await self.db.add_auth_attempt("sb", "s1", "anna", "pw", False,
                                       False, t0)
        attempts = await self.db.list_auth_attempts(sort="username",
                                                    descending=False)
        self.assertEqual([r[3] for r in attempts], ["anna", "zed"])
        attackers = await self.db.list_attackers(sort="attacker_ip",
                                                 descending=False)
        self.assertEqual([r[0] for r in attackers],
                         ["1.1.1.1", "2.2.2.2"])
        attackers_bad = await self.db.list_attackers(sort="nope")
        self.assertEqual([r[0] for r in attackers_bad],
                         ["2.2.2.2", "1.1.1.1"])

    async def test_server_settings_crud(self):
        self.assertIsNone(await self.db.get_setting("virustotal.api_key"))
        await self.db.set_setting("virustotal.api_key", "k1")
        self.assertEqual(await self.db.get_setting("virustotal.api_key"),
                         "k1")
        await self.db.set_setting("virustotal.api_key", "k2")
        self.assertEqual(await self.db.get_setting("virustotal.api_key"),
                         "k2")
        await self.db.delete_setting("virustotal.api_key")
        self.assertIsNone(await self.db.get_setting("virustotal.api_key"))

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
