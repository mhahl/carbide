import os
import tempfile
import unittest

from carbide.common import protocol
from carbide.common.util import b64d, sha256_hex
from carbide.sensor.recorder import Recorder
from carbide.sensor.spool import Spool


class RecorderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.spool = Spool(os.path.join(self.tmp.name, "spool"))
        self.rec = Recorder(self.spool, "s1", "sess1")

    def tearDown(self):
        self.tmp.cleanup()

    def _kinds(self):
        return [r["kind"] for _s, r in self.spool.pending()]

    def test_lifecycle_and_auth(self):
        self.rec.session_start("1.2.3.4", "root")
        self.rec.auth_attempt("root", "pw", True, True)
        self.rec.session_container("cid", True)
        self.rec.session_end("eof")
        self.assertEqual(self._kinds(), [
            protocol.KIND_SESSION_START, protocol.KIND_AUTH_ATTEMPT,
            protocol.KIND_SESSION_CONTAINER, protocol.KIND_SESSION_END])
        recs = [r for _s, r in self.spool.pending()]
        self.assertEqual(recs[0]["attacker_ip"], "1.2.3.4")
        self.assertTrue(all(r["session_id"] == "sess1" for r in recs))

    def test_transcript_chunking(self):
        data = bytes(range(256)) * 1000
        ids = self.rec.transcript("ch0", "out", "stdout", data)
        self.assertTrue(len(ids) > 1)
        recs = [r for _s, r in self.spool.pending()]
        self.assertTrue(all(r["kind"] == protocol.KIND_TRANSCRIPT
                            for r in recs))
        joined = b"".join(b64d(r["data_b64"]) for r in recs)
        self.assertEqual(joined, data)

    def test_evidence_chunks(self):
        data = b"A" * (protocol.CHUNK_BYTES + 10)
        sha = self.rec.evidence("up/x", data)
        self.assertEqual(sha, sha256_hex(data))
        recs = [r for _s, r in self.spool.pending()]
        self.assertEqual(recs[0]["kind"], protocol.KIND_BLOB_META)
        self.assertEqual(recs[0]["name"], "up/x")
        chunks = [r for r in recs if r["kind"] == protocol.KIND_BLOB_CHUNK]
        self.assertEqual(len(chunks), 2)
        self.assertTrue(chunks[-1]["last"])
        joined = b"".join(b64d(r["data_b64"]) for r in chunks)
        self.assertEqual(joined, data)


if __name__ == "__main__":
    unittest.main()
