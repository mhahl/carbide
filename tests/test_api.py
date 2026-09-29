import asyncio
import os
import socket
import tempfile
import unittest

from carbide.common import protocol
from carbide.common.blobstore import BlobStore
from carbide.common.config import validate
from carbide.common.util import BindError, b64e, new_id, sha256_hex, utcnow_iso
from carbide.sensor.recorder import Recorder
from carbide.sensor.spool import Spool
from carbide.server.api import ServerAPI
from carbide.server.forensics import Forensics
from carbide.server.pool import Pool
from tests.fakes import FakeDatabase, FakePodman


def make_config(**over):
    raw = {
        "role": "server",
        "server": {"sensor_token": "tok", "db_dsn": "x",
                   "blob_dir": "y", "api_port": 8440},
        "podman": {"image": "img", "pool_size": 0,
                   "port_range_start": 22000, "port_range_end": 22010},
        "affinity": {"keep_warm_minutes": 0},
        "quotas": {"session_max_bytes": 10**6},
    }
    for section, values in over.items():
        raw.setdefault(section, {}).update(values)
    cfg = validate(raw)
    return cfg


class ApiTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = FakeDatabase()
        self.pod = FakePodman()
        cfg = make_config()
        self.blobs = BlobStore(os.path.join(self.tmp.name, "blobs"), 10**9)
        self.pool = Pool(self.pod, self.db, cfg)
        await self.pool.start()

        async def _ready(*args, **kwargs):
            return None
        self.pool._wait_sshd = _ready
        forensics = Forensics(self.pool, self.pod, self.db, self.blobs,
                              cfg)
        self.api = ServerAPI(self.db, self.pool, forensics, self.blobs,
                             cfg)
        self.server = await asyncio.start_server(
            self.api._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        self.reader, self.writer = await asyncio.open_connection(
            "127.0.0.1", self.port)
        await self.hello("s1", "tok")

    async def asyncTearDown(self):
        self.writer.close()
        self.server.close()
        await self.server.wait_closed()

    async def rpc(self, msg):
        self.writer.write(protocol.encode(msg))
        await self.writer.drain()
        return protocol.decode(await self.reader.readline())

    async def hello(self, sensor_id, token):
        return await self.rpc(protocol.new_envelope(
            "hello", sensor_id=sensor_id, token=token))

    async def send_record(self, record):
        return await self.rpc(protocol.new_envelope(
            "record", record_id=record["record_id"], record=record))

    async def test_run_bind_conflict_raises_bind_error(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        self.addCleanup(sock.close)
        port = sock.getsockname()[1]
        cfg = make_config(server={"api_addr": "127.0.0.1",
                                  "api_port": port})
        forensics = Forensics(self.pool, self.pod, self.db, self.blobs,
                              cfg)
        api = ServerAPI(self.db, self.pool, forensics, self.blobs, cfg)
        with self.assertRaises(BindError) as ctx:
            await api.run()
        self.assertIn("already in use", str(ctx.exception))

    async def test_bad_hello_rejected(self):
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", self.port)
        writer.write(protocol.encode(protocol.new_envelope(
            "hello", sensor_id="s1", token="wrong")))
        await writer.drain()
        reply = protocol.decode(await reader.readline())
        writer.close()
        self.assertFalse(reply["ok"])

    async def test_shared_token_links_any_sensor_id(self):
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", self.port)
        writer.write(protocol.encode(protocol.new_envelope(
            "hello", sensor_id="brand-new-sensor", token="tok")))
        await writer.drain()
        reply = protocol.decode(await reader.readline())
        writer.close()
        self.assertTrue(reply["ok"])

    async def test_bad_sensor_id_rejected(self):
        for bad_id in ("", "x" * 129, None, 42):
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", self.port)
            writer.write(protocol.encode(protocol.new_envelope(
                "hello", sensor_id=bad_id, token="tok")))
            await writer.drain()
            reply = protocol.decode(await reader.readline())
            writer.close()
            self.assertFalse(reply["ok"], bad_id)

    async def test_hello_ok_and_container_flow(self):
        reply = await self.rpc(protocol.new_envelope(
            "container_for", attacker_ip="1.2.3.4"))
        self.assertTrue(reply["ok"])
        self.assertTrue(reply["fresh"])
        cid = reply["container_id"]
        reply2 = await self.rpc(protocol.new_envelope(
            "container_for", attacker_ip="1.2.3.4"))
        self.assertFalse(reply2["fresh"])
        self.assertEqual(reply2["container_id"], cid)

    async def test_record_idempotent(self):
        rec = {"record_id": new_id(), "kind": "auth_attempt",
               "session_id": "s", "sensor_id": "s1", "at": utcnow_iso(),
               "username": "u", "password": "p", "accepted": False,
               "matched_list": False}
        r1 = await self.send_record(rec)
        r2 = await self.send_record(rec)
        self.assertTrue(r1["ok"])
        self.assertTrue(r2["ok"])
        self.assertEqual(len(self.db.attempts), 1)

    async def test_malformed_record_refused(self):
        reply = await self.send_record({"record_id": new_id()})
        self.assertFalse(reply["ok"])

    async def test_evidence_roundtrip(self):
        spool = Spool(os.path.join(self.tmp.name, "spool"))
        rec = Recorder(spool, "s1", "sess-e")
        rec.session_start("5.6.7.8", "root")
        data = b"B" * 70000
        sha = rec.evidence("up/tool", data)
        self.assertEqual(sha, sha256_hex(data))
        for _slot, record in spool.pending():
            reply = await self.send_record(record)
            self.assertTrue(reply["ok"], reply)
        stored = self.blobs.get_bytes(sha)
        self.assertEqual(stored, data)
        names = [f[1] for f in self.db.files]
        self.assertIn("up/tool", names)
        session = await self.db.get_session("sess-e")
        self.assertEqual(session[2], "5.6.7.8")

    async def test_session_end_triggers_forensics(self):
        ep = await self.rpc(protocol.new_envelope(
            "container_for", attacker_ip="9.9.9.9"))
        cid = ep["container_id"]
        self.pod.write_file(cid, "/tmp/pwn", b"evil")
        spool = Spool(os.path.join(self.tmp.name, "spool2"))
        rec = Recorder(spool, "s1", "sess-f")
        rec.session_start("9.9.9.9", "root")
        rec.session_container(cid, True)
        rec.transcript("ch1", "in", "stdin", b"echo hi\n")
        rec.session_end("eof")
        for _slot, record in spool.pending():
            reply = await self.send_record(record)
            self.assertTrue(reply["ok"], reply)
        for _ in range(100):
            if await self.db.get_report("sess-f"):
                break
            await asyncio.sleep(0.05)
        md, _js = await self.db.get_report("sess-f")
        self.assertIn("/tmp/pwn", md)
        aff = await self.db.get_affinity("s1", "9.9.9.9")
        self.assertTrue(aff["has_activity"])

    async def test_quota_drops_transcript(self):
        cfg = make_config(quotas={"session_max_bytes": 10})
        blobs = BlobStore(os.path.join(self.tmp.name, "b2"), 10**9)
        pool = Pool(self.pod, self.db, cfg)
        forensics = Forensics(pool, self.pod, self.db, blobs, cfg)
        api = ServerAPI(self.db, pool, forensics, blobs, cfg)
        server = await asyncio.start_server(
            api._handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(protocol.encode(protocol.new_envelope(
            "hello", sensor_id="s1", token="tok")))
        await writer.drain()
        await reader.readline()

        def send(record):
            writer.write(protocol.encode(protocol.new_envelope(
                "record", record_id=record["record_id"], record=record)))
            return reader.readline()
        reply = protocol.decode(await send(
            {"record_id": new_id(), "kind": "transcript",
             "session_id": "q", "sensor_id": "s1",
             "at": utcnow_iso(), "channel": "c", "direction": "in",
             "stream": "stdin", "seq": 0,
             "data_b64": b64e(b"x" * 100)}))
        self.assertTrue(reply["ok"])
        self.assertEqual(self.db.transcripts, [])
        session = await self.db.get_session("q")
        self.assertTrue(session[6])
        writer.close()
        server.close()
        await server.wait_closed()


class ApiShutdownTest(unittest.IsolatedAsyncioTestCase):
    async def test_run_drains_inflight_handlers(self):
        # A handler stuck in the database when run() is cancelled must be
        # torn down before run() returns: touching the db after close()
        # segfaults the psycopg C accelerator (use-after-free).
        entered = asyncio.Event()
        release = asyncio.Event()

        class BlockingDatabase(FakeDatabase):
            async def claim_record(self, record_id):
                entered.set()
                await release.wait()
                return await super().claim_record(record_id)

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = BlockingDatabase()
        pod = FakePodman()
        import socket
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
        probe.close()
        cfg = make_config(server={"api_port": free})
        blobs = BlobStore(os.path.join(tmp.name, "blobs"), 10**9)
        pool = Pool(pod, db, cfg)
        await pool.start()
        forensics = Forensics(pool, pod, db, blobs, cfg)
        api = ServerAPI(db, pool, forensics, blobs, cfg)
        task = asyncio.create_task(api.run())
        for _ in range(100):
            if api._server is not None:
                break
            await asyncio.sleep(0.05)
        self.assertIsNotNone(api._server)
        port = api._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port)
        writer.write(protocol.encode(protocol.new_envelope(
            "hello", sensor_id="s1", token="tok")))
        await writer.drain()
        reply = protocol.decode(await reader.readline())
        self.assertTrue(reply["ok"])
        writer.write(protocol.encode(protocol.new_envelope(
            "record", record_id="r1", record={
                "record_id": "r1", "kind": "session_start",
                "session_id": "s", "attacker_ip": "1.2.3.4",
                "username": "root", "at": utcnow_iso()})))
        await writer.drain()
        await asyncio.wait_for(entered.wait(), timeout=10)
        self.assertEqual(len(api._handlers), 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(len(api._handlers), 0)
        writer.close()


if __name__ == "__main__":
    unittest.main()
