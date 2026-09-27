"""Live fleet tests: real Postgres, real Podman containers, real Squid, real
SSH clients. Two sensors against one server.

Needs: podman + image build, postgres binaries, squid, logrotate (last one
only for the rotation test). Skips cleanly otherwise.
"""
import asyncio
import functools
import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import asyncssh

from tests.pgcluster import PgCluster, free_port, postgres_available

from carbide.common.config import validate
from carbide.sensor.app import SensorApp
from carbide.server.app import ServerApp
from carbide.server.db import Database
from carbide.server.squid import parse_line

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE = "carbide-honeypot:latest"

FIX = {}


def podman_works() -> bool:
    try:
        result = subprocess.run(["podman", "info", "--format", "{{.Host.Arch}}"],
                                capture_output=True, timeout=30)
        return result.returncode == 0
    except Exception:
        return False


def network_gateway_and_subnet(network: str):
    name = network or "podman"
    try:
        out = subprocess.run(["podman", "network", "inspect", name],
                             capture_output=True, text=True, timeout=30)
        data = json.loads(out.stdout or "[]")
        # netavark format
        for entry in data[0].get("subnets", []):
            if entry.get("gateway"):
                return entry["gateway"], entry.get("subnet", "")
        # CNI plugins format
        for plugin in data[0].get("plugins", []):
            ipam = plugin.get("ipam") or {}
            for ranges in ipam.get("ranges", []):
                for entry in ranges:
                    if entry.get("gateway"):
                        return entry["gateway"], entry.get("subnet", "")
    except Exception:
        pass
    return "10.88.0.1", "10.88.0.0/16"


def setUpModule():
    if os.environ.get("CARBIDE_LIVE_TESTS") != "1":
        raise unittest.SkipTest(
            "live fleet tests need CARBIDE_LIVE_TESTS=1 "
            "(podman, postgres, squid, several minutes)")
    if not postgres_available():
        raise unittest.SkipTest("postgres binaries/user missing")
    if not podman_works():
        raise unittest.SkipTest("podman unavailable")
    if not shutil.which("squid"):
        raise unittest.SkipTest("squid missing")
    tmp = tempfile.TemporaryDirectory(prefix="carbide-live-")
    FIX["tmp"] = tmp
    base = tmp.name
    # image
    have = subprocess.run(["podman", "image", "exists", IMAGE])
    if have.returncode != 0:
        built = subprocess.run(
            ["podman", "build", "-t", IMAGE,
             os.path.join(ROOT, "image")],
            capture_output=True, text=True, timeout=600)
        if built.returncode != 0:
            raise unittest.SkipTest(f"image build failed: {built.stderr[-500:]}")
    # postgres
    pg = PgCluster()
    FIX["dsn"] = pg.start()
    FIX["pg"] = pg
    # podman API service
    sock = os.path.join(base, "podman.sock")
    FIX["podman_sock"] = sock
    svc = subprocess.Popen(
        ["podman", "system", "service", "--timeout", "0",
         f"unix://{sock}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    FIX["podman_svc"] = svc
    for _ in range(100):
        if os.path.exists(sock):
            break
        time.sleep(0.2)
    if not os.path.exists(sock):
        raise unittest.SkipTest("podman system service did not start")
    FIX["podman_url"] = f"unix://{sock}"
    # gateway/subnet for squid + explicit proxy env
    gateway, subnet = network_gateway_and_subnet("")
    FIX["gateway"], FIX["subnet"] = gateway, subnet
    # local HTTP target (deterministic curl destination through the proxy)
    webdir = os.path.join(base, "web")
    os.makedirs(webdir)
    with open(os.path.join(webdir, "hello.txt"), "w") as fh:
        fh.write("proxied-hello\n")
    handler = functools.partial(SimpleHTTPRequestHandler, directory=webdir)
    # Bind all interfaces: squid reaches this target via the podman
    # gateway address, which loopback-only would refuse.
    httpd = ThreadingHTTPServer(("0.0.0.0", 0), handler)
    FIX["http_port"] = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    FIX["httpd"] = httpd
    # squid: shipped config with test paths/ports, run as the squid user
    # (squid refuses root) with a work dir it owns.
    squid_port = free_port()
    FIX["squid_port"] = squid_port
    sqdir = os.path.join(base, "squidrun")
    os.makedirs(sqdir)
    cert = os.path.join(sqdir, "splice-dummy.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-nodes", "-days", "2", "-subj", "/CN=carbide-test",
                    "-keyout", cert, "-out", cert],
                   check=True, capture_output=True, timeout=60)
    with open(os.path.join(ROOT, "squid", "squid.conf")) as fh:
        conf = fh.read()
    conf = conf.replace("http_port 3128",
                        f"http_port 0.0.0.0:{squid_port}")
    conf = conf.replace("http_port 3129 intercept",
                        f"http_port 127.0.0.1:{free_port()} intercept")
    conf = conf.replace("https_port 3130 intercept ssl-bump",
                        f"https_port 127.0.0.1:{free_port()} intercept ssl-bump")
    conf = conf.replace("/etc/squid/splice-dummy.pem", cert)
    conf = conf.replace("acl containers src 10.88.0.0/16",
                        f"acl containers src {subnet} 127.0.0.1")
    conf = conf.replace("/var/log/squid/access.log",
                        os.path.join(sqdir, "access.log"))
    conf += (f"\npid_filename {sqdir}/squid.pid\ncoredump_dir {sqdir}\n"
             f"cache_log {sqdir}/cache.log\n")
    squid_conf = os.path.join(sqdir, "squid.conf")
    with open(squid_conf, "w") as fh:
        fh.write(conf)
    FIX["squid_conf"] = squid_conf
    FIX["squid_log"] = os.path.join(sqdir, "access.log")
    parsed = subprocess.run(["squid", "-k", "parse", "-f", squid_conf],
                            capture_output=True, text=True, timeout=60)
    if parsed.returncode != 0:
        raise unittest.SkipTest(f"squid parse failed: {parsed.stderr[-2000:]}")
    os.chmod(base, 0o755)
    os.system(f"chown -R squid:squid {sqdir}")
    squid_err = os.path.join(base, "squid-stderr.log")
    FIX["squid_err"] = squid_err
    with open(squid_err, "wb") as errfh:
        squid = subprocess.Popen(
            ["runuser", "-u", "squid", "--", "squid", "-N",
             "-f", squid_conf],
            stdout=subprocess.DEVNULL, stderr=errfh)
    FIX["squid"] = squid
    for _ in range(100):
        sock_test = socket.socket()
        try:
            sock_test.connect(("127.0.0.1", squid_port))
            break
        except OSError:
            time.sleep(0.2)
        finally:
            sock_test.close()
    else:
        detail = ""
        try:
            with open(FIX["squid_err"], errors="replace") as fh:
                detail = fh.read()[-1500:]
        except OSError:
            pass
        raise unittest.SkipTest(f"squid did not start: {detail}")


def tearDownModule():
    for key in ("squid", "podman_svc"):
        proc = FIX.get(key)
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=15)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    # remove all carbide test containers/snapshots (affinities persist by
    # design, so the suite cleans up after itself explicitly)
    try:
        out = subprocess.run(
            ["podman", "ps", "-a", "--filter", "label=carbide",
             "--format", "{{.ID}}"], capture_output=True, text=True,
            timeout=60)
        ids = out.stdout.split()
        if ids:
            subprocess.run(["podman", "rm", "-f", *ids],
                           capture_output=True, timeout=120)
        out = subprocess.run(
            ["podman", "images", "--filter", "reference=carbide-snap*",
             "--format", "{{.ID}}"], capture_output=True, text=True,
            timeout=60)
        ids = out.stdout.split()
        if ids:
            subprocess.run(["podman", "rmi", "-f", *ids],
                           capture_output=True, timeout=120)
        subprocess.run(["podman", "rm", "-f", "carbide-ref"],
                       capture_output=True, timeout=60)
    except Exception:
        pass
    httpd = FIX.get("httpd")
    if httpd is not None:
        httpd.shutdown()
        httpd.server_close()
    pg = FIX.get("pg")
    if pg is not None:
        pg.stop()
    tmp = FIX.get("tmp")
    if tmp is not None:
        tmp.cleanup()


def server_config(name, api_port, blob_max=10**9, session_max=10**7,
                  port_start=23000, port_end=23020):
    base = FIX["tmp"].name
    blob_dir = os.path.join(base, f"blobs-{name}")
    return validate({
        "role": "server",
        "server": {"tokens": {"s1": "tok1", "s2": "tok2"},
                   "db_dsn": FIX["dsn"], "blob_dir": blob_dir,
                   "api_addr": "127.0.0.1", "api_port": api_port},
        "podman": {"socket": FIX["podman_url"], "image": IMAGE,
                   "port_range_start": port_start,
                   "port_range_end": port_end, "pool_size": 1,
                   "ssh_host": "127.0.0.1"},
        "affinity": {"keep_warm_minutes": 0, "snapshot_retention": 3},
        "squid": {"enabled": True, "mode": "explicit",
                  "explicit_proxy":
                      f"http://{FIX['gateway']}:{FIX['squid_port']}",
                  "log_path": FIX["squid_log"]},
        "quotas": {"blob_max_bytes": blob_max,
                   "session_max_bytes": session_max},
    })


def sensor_config(sensor_id, token, port, server_port):
    base = FIX["tmp"].name
    return validate({
        "role": "sensor",
        "sensor": {"listen_addr": "127.0.0.1", "listen_port": port,
                   "host_key_path": os.path.join(
                       base, f"sshkey-{sensor_id}"),
                   "server_host": "127.0.0.1", "server_port": server_port,
                   "sensor_id": sensor_id, "token": token,
                   "spool_dir": os.path.join(base, f"spool-{sensor_id}")},
        "auth": {"passwords": ["test-accept"], "accept_probability": 0.0},
    })


async def wait_for(predicate, timeout=60.0, interval=0.2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = await predicate()
        if value:
            return value
        await asyncio.sleep(interval)
    raise AssertionError("timed out waiting for condition")


async def cancel_task(task):
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


async def tcp_up(host, port):
    try:
        _r, w = await asyncio.open_connection(host, port)
        w.close()
        return True
    except OSError:
        return False


def spool_empty(path):
    async def check():
        try:
            left = [f for f in os.listdir(path) if f.endswith(".json")]
        except FileNotFoundError:
            return True
        return not left or None
    return check


async def fetch_rows(db, sql, params=()):
    async with db._lock:
        async with db._conn.cursor() as cur:
            await cur.execute(sql, params)
            return await cur.fetchall()


async def exec_sql(db, sql, params=()):
    async with db._lock:
        async with db._conn.cursor() as cur:
            await cur.execute(sql, params)
        await db._conn.commit()


class SquidConfTest(unittest.TestCase):
    def test_a_shipped_conf_serves_and_logs(self):
        import urllib.request
        proxy = urllib.request.ProxyHandler(
            {"http": f"http://127.0.0.1:{FIX['squid_port']}"})
        opener = urllib.request.build_opener(proxy)
        url = f"http://127.0.0.1:{FIX['http_port']}/hello.txt"
        with opener.open(url, timeout=20) as resp:
            self.assertEqual(resp.read(), b"proxied-hello\n")
        time.sleep(2)  # let squid flush the access log
        with open(FIX["squid_log"]) as fh:
            lines = [line for line in fh.read().splitlines() if line.strip()]
        self.assertTrue(lines, "squid wrote no access log")
        hit = parse_line(lines[-1])
        self.assertIsNotNone(hit, f"unparseable squid line: {lines[-1]!r}")
        self.assertEqual(hit["url"], url)


class FleetTest(unittest.IsolatedAsyncioTestCase):
    def _blob_bytes(self, _rows, sha):
        import glob
        matches = glob.glob(os.path.join(
            FIX["tmp"].name, "blobs-main", "*", sha))
        self.assertEqual(len(matches), 1, sha)
        with open(matches[0], "rb") as fh:
            return fh.read()

    async def test_b_full_fleet_e2e(self):
        base = FIX["tmp"].name
        api_port = free_port()
        server = ServerApp(server_config("main", api_port))
        server_task = asyncio.create_task(server.run())
        self.addAsyncCleanup(cancel_task, server_task)
        await wait_for(lambda: tcp_up("127.0.0.1", api_port), timeout=90)
        db = Database(FIX["dsn"])
        await db.connect()
        self.addAsyncCleanup(db.close)

        p1, p2 = free_port(), free_port()
        s1 = SensorApp(sensor_config("s1", "tok1", p1, api_port))
        from carbide.sensor.__main__ import ensure_host_key
        ensure_host_key(os.path.join(base, "sshkey-s1"))
        t1 = asyncio.create_task(s1.run())
        self.addAsyncCleanup(cancel_task, t1)
        s2 = SensorApp(sensor_config("s2", "tok2", p2, api_port))
        ensure_host_key(os.path.join(base, "sshkey-s2"))
        t2 = asyncio.create_task(s2.run())
        self.addAsyncCleanup(cancel_task, t2)
        await wait_for(lambda: tcp_up("127.0.0.1", p1), timeout=30)
        await wait_for(lambda: tcp_up("127.0.0.1", p2), timeout=30)

        # -- attacker A (127.0.0.2) on sensor 1 -------------------------
        with self.subTest("reject then accept"):
            try:
                async with asyncssh.connect(
                        "127.0.0.1", p1, username="root",
                        password="wrong", known_hosts=None,
                        local_addr=("127.0.0.2", 0)):
                    pass
                self.fail("wrong password accepted")
            except asyncssh.PermissionDenied:
                pass
            conn = await asyncssh.connect(
                "127.0.0.1", p1, username="root", password="test-accept",
                known_hosts=None, local_addr=("127.0.0.2", 0))
        with self.subTest("shell + files + proxy"):
            try:
                result = await conn.run("echo hello-attacker")
                self.assertEqual(result.stdout.strip(), "hello-attacker")
                await conn.run("echo secret-data > /tmp/pwned.txt")
                async with conn.start_sftp_client() as sftp:
                    local_up = os.path.join(base, "up.bin")
                    with open(local_up, "wb") as fh:
                        fh.write(b"sftp-upload-bytes")
                    await sftp.put(local_up, "/tmp/via-sftp.bin")
                    await sftp.get("/etc/motd", os.path.join(base, "motd"))
                local_scp = os.path.join(base, "scp.bin")
                with open(local_scp, "wb") as fh:
                    fh.write(b"scp-upload-bytes")
                await asyncssh.scp(local_scp, (conn, "/tmp/via-scp.bin"))
                curl = await conn.run(
                    f"curl -s http://{FIX['gateway']}:{FIX['http_port']}"
                    "/hello.txt -o /tmp/web.txt; cat /tmp/web.txt")
                self.assertIn("proxied-hello", curl.stdout)
            finally:
                conn.close()
                await conn.wait_closed()

        # -- evidence landed --------------------------------------------
        with self.subTest("evidence in db"):
            async def report_ready():
                aff = await db.get_affinity("s1", "127.0.0.2")
                if not aff:
                    return None
                latest = await db.latest_session("s1", "127.0.0.2")
                if not latest:
                    return None
                rep = await db.get_report(latest[0])
                return (latest[0], aff, rep) if rep else None
            session_id, aff, (md, js) = await wait_for(report_ready,
                                                       timeout=120)
            payload = json.loads(js)
            paths = {c["path"] for c in payload["changes"]}
            self.assertIn("/tmp/pwned.txt", paths)
            self.assertIn("/tmp/via-sftp.bin", paths)
            self.assertIn("/tmp/via-scp.bin", paths)
            self.assertIn("secret-data", md)
            # transcript holds the attacker's commands
            cur = await fetch_rows(
                db, "SELECT data FROM transcripts WHERE session_id = %s "
                "ORDER BY id", (session_id,))
            blob = b"".join(bytes(r[0]) for r in cur)
            self.assertIn(b"echo hello-attacker", blob)
            # auth attempts: one reject, one accept
            cur = await fetch_rows(
                db, "SELECT accepted FROM auth_attempts WHERE session_id "
                "= %s ORDER BY id", (session_id,))
            # (reject attempt was a different connection/session; this
            # session has exactly its own accept)
            self.assertEqual([bool(r[0]) for r in cur], [True])
            # squid attribution
            cur = await fetch_rows(
                db, "SELECT url FROM squid_hits WHERE session_id = %s",
                (session_id,))
            self.assertTrue(any("hello.txt" in r[0] for r in cur),
                            "no squid hit attributed to session")
            # carved SFTP/SCP files landed with their bytes
            cur = await fetch_rows(
                db, "SELECT name, blob_sha, size FROM session_files "
                "WHERE session_id = %s", (session_id,))
            by_name = {r[0]: r for r in cur}
            ups = [n for n in by_name
                   if n.endswith("sftp-upload:/tmp/via-sftp.bin")]
            downs = [n for n in by_name
                     if n.endswith("sftp-download:/etc/motd")]
            self.assertEqual(len(ups), 1, sorted(by_name))
            self.assertEqual(len(downs), 1, sorted(by_name))
            self.assertEqual(
                self._blob_bytes(cur, by_name[ups[0]][1]),
                b"sftp-upload-bytes")
            scp_names = [n for n in by_name
                         if n.endswith("/via-scp.bin") and "scp-upload" in n]
            self.assertTrue(scp_names, sorted(by_name))
            # blobs verify
            cur = await fetch_rows(db, "SELECT sha256, path FROM blobs")
            self.assertTrue(cur)
            for sha, path in cur:
                with open(path, "rb") as fh:
                    self.assertEqual(hashlib.sha256(fh.read()).hexdigest(),
                                     sha)

        with self.subTest("same ip resumes container"):
            conn2 = await asyncssh.connect(
                "127.0.0.1", p1, username="root", password="test-accept",
                known_hosts=None, local_addr=("127.0.0.2", 0))
            try:
                result = await conn2.run("cat /tmp/pwned.txt")
                self.assertEqual(result.stdout.strip(), "secret-data")
            finally:
                conn2.close()
                await conn2.wait_closed()
            aff2 = await db.get_affinity("s1", "127.0.0.2")
            self.assertEqual(aff2["container_id"], aff["container_id"])

        with self.subTest("same ip other sensor gets own container"):
            conn3 = await asyncssh.connect(
                "127.0.0.1", p2, username="root", password="test-accept",
                known_hosts=None, local_addr=("127.0.0.2", 0))
            try:
                result = await conn3.run(
                    "cat /tmp/pwned.txt; echo rc=$?")
                self.assertIn("rc=1", result.stdout.replace(" ", ""))
            finally:
                conn3.close()
                await conn3.wait_closed()
            aff3 = await db.get_affinity("s2", "127.0.0.2")
            self.assertNotEqual(aff3["container_id"], aff["container_id"])

        with self.subTest("new ip gets fresh container"):
            conn4 = await asyncssh.connect(
                "127.0.0.1", p1, username="root", password="test-accept",
                known_hosts=None, local_addr=("127.0.0.3", 0))
            try:
                result = await conn4.run(
                    "cat /tmp/pwned.txt; echo rc=$?")
                self.assertIn("rc=1", result.stdout.replace(" ", ""))
            finally:
                conn4.close()
                await conn4.wait_closed()
            aff4 = await db.get_affinity("s1", "127.0.0.3")
            self.assertNotEqual(aff4["container_id"], aff["container_id"])

        # -- outage: evidence spools, then forwards exactly once --------
        with self.subTest("server outage spool recovery"):
            await cancel_task(server_task)
            conn5 = await asyncssh.connect(
                "127.0.0.1", p1, username="root", password="test-accept",
                known_hosts=None, local_addr=("127.0.0.4", 0))
            try:
                await conn5.run("echo during-outage")
            except Exception:
                pass  # channels fail closed without a server
            finally:
                conn5.close()
                await conn5.wait_closed()
            await asyncio.sleep(2)
            spooled = os.listdir(os.path.join(base, "spool-s1"))
            self.assertTrue([f for f in spooled if f.endswith(".json")],
                            "nothing spooled during outage")
            server2 = ServerApp(server_config("main", api_port))
            server_task2 = asyncio.create_task(server2.run())
            self.addAsyncCleanup(cancel_task, server_task2)
            await wait_for(lambda: tcp_up("127.0.0.1", api_port),
                           timeout=90)

            async def outage_session_complete():
                latest = await db.latest_session("s1", "127.0.0.4")
                if not latest:
                    return None
                cur = await fetch_rows(
                    db, "SELECT accepted FROM auth_attempts WHERE "
                    "session_id = %s", (latest[0],))
                return latest[0] if cur else None
            out_sid = await wait_for(outage_session_complete, timeout=60)
            cur = await fetch_rows(
                db, "SELECT COUNT(*) FROM auth_attempts WHERE session_id "
                "= %s", (out_sid,))
            self.assertEqual(cur[0][0], 1)  # forwarded, not duplicated
            # spool drained
            await wait_for(spool_empty(
                os.path.join(base, "spool-s1")), timeout=60)

        # -- live eviction with final archive -----------------------------
        with self.subTest("eviction archives then removes"):
            import datetime
            aff_victim = await db.get_affinity("s1", "127.0.0.3")
            victim_cid = aff_victim["container_id"]
            await exec_sql(
                db, "UPDATE affinities SET last_session_end = %s WHERE "
                "sensor_id = 's1' AND attacker_ip = '127.0.0.3'",
                (datetime.datetime.now(datetime.timezone.utc)
                 - datetime.timedelta(days=60),))
            future = (datetime.datetime.now(datetime.timezone.utc)
                      + datetime.timedelta(hours=1))
            await server2.eviction.run_once(now=future)
            self.assertIsNone(await db.get_affinity("s1", "127.0.0.3"))
            gone = subprocess.run(
                ["podman", "inspect", victim_cid], capture_output=True)
            self.assertNotEqual(gone.returncode, 0)
            latest = await db.latest_session("s1", "127.0.0.3")
            rep = await db.get_report(latest[0])
            self.assertIsNotNone(rep)
            self.assertIn("eviction", rep[0])

class QuotaLiveTest(unittest.IsolatedAsyncioTestCase):
    async def test_c_session_quota_enforced_live(self):
        api_port = free_port()
        server = ServerApp(server_config("quota", api_port,
                                         session_max=2000,
                                         port_start=23100,
                                         port_end=23110))
        task = asyncio.create_task(server.run())
        try:
            await wait_for(lambda: tcp_up("127.0.0.1", api_port),
                           timeout=90)
            db = Database(FIX["dsn"])
            await db.connect()
            try:
                sport = free_port()
                sensor = SensorApp(sensor_config("s1", "tok1", sport,
                                                 api_port))
                from carbide.sensor.__main__ import ensure_host_key
                ensure_host_key(os.path.join(FIX["tmp"].name,
                                             "sshkey-s1"))
                stask = asyncio.create_task(sensor.run())
                try:
                    await wait_for(lambda: tcp_up("127.0.0.1", sport),
                                   timeout=30)
                    conn = await asyncssh.connect(
                        "127.0.0.1", sport, username="root",
                        password="test-accept", known_hosts=None)
                    try:
                        await conn.run("echo small-ok")
                        await conn.run("head -c 6000 /dev/urandom | od -An | head -40")
                    finally:
                        conn.close()
                        await conn.wait_closed()

                    async def quota_row():
                        latest = await db.latest_session("s1", "127.0.0.1")
                        if not latest:
                            return None
                        row = await db.get_session(latest[0])
                        # ended_at set + over_quota tripped: all evidence
                        # drained through the quota gate.
                        if row and row[8] and row[6]:
                            return row
                        return None
                    row = await wait_for(quota_row, timeout=60)
                    self.assertTrue(row[6])  # over_quota
                    total = await db.session_byte_count(row[0])
                    self.assertLess(total, 2000 + 65536)
                finally:
                    stask.cancel()
                    try:
                        await stask
                    except (asyncio.CancelledError, Exception):
                        pass
            finally:
                await db.close()
        finally:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass


class LogrotateTest(unittest.TestCase):
    def test_d_logrotate_runs_live(self):
        if not shutil.which("logrotate"):
            self.skipTest("logrotate missing")
        base = FIX["tmp"].name
        # Mirror production: carbide logs and the squid log live in
        # different directories (one dir would make the *.log stanza
        # swallow access.log: "duplicate log entry").
        cdir = os.path.join(base, "rot", "carbide")
        sqdir = os.path.join(base, "rot", "squid")
        os.makedirs(cdir)
        os.makedirs(sqdir)
        with open(os.path.join(ROOT, "packaging", "logrotate.carbide")) as fh:
            conf = fh.read()
        conf = conf.replace("/var/log/carbide/*.log",
                            f"{cdir}/*.log")
        conf = conf.replace("/var/log/squid/access.log",
                            f"{sqdir}/access.log")
        conf_path = os.path.join(base, "logrotate.conf")
        with open(conf_path, "w") as fh:
            fh.write(conf)
        with open(os.path.join(cdir, "carbide-server.log"), "w") as fh:
            fh.write("x" * 100 + "\n")
        with open(os.path.join(sqdir, "access.log"), "w") as fh:
            fh.write("x" * 100 + "\n")
        result = subprocess.run(
            ["logrotate", "-f", "-s", os.path.join(base, "logrotate.state"),
             conf_path], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        rotated = os.listdir(cdir) + os.listdir(sqdir)
        self.assertTrue(any(n.endswith(".1") for n in rotated), rotated)


if __name__ == "__main__":
    unittest.main()
