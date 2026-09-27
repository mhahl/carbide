import os
import tempfile
import unittest

from carbide.common.blobstore import BlobStore, QuotaExceeded
from carbide.common.util import sha256_hex


class BlobStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = BlobStore(os.path.join(self.tmp.name, "blobs"), 1024)

    def tearDown(self):
        self.tmp.cleanup()

    def test_put_get_roundtrip(self):
        ref = self.store.put_bytes(b"hello")
        self.assertEqual(ref.sha256, sha256_hex(b"hello"))
        self.assertEqual(self.store.get_bytes(ref.sha256), b"hello")

    def test_dedupe(self):
        a = self.store.put_bytes(b"same")
        b = self.store.put_bytes(b"same")
        self.assertEqual(a, b)
        self.assertEqual(self.store.total_bytes, 4)

    def test_quota(self):
        self.store.put_bytes(b"x" * 1000)
        with self.assertRaises(QuotaExceeded):
            self.store.put_bytes(b"y" * 100)
        self.assertFalse(self.store.exists(sha256_hex(b"y" * 100)))

    def test_delete(self):
        ref = self.store.put_bytes(b"bye")
        self.assertTrue(self.store.delete(ref.sha256))
        self.assertFalse(self.store.exists(ref.sha256))
        self.assertFalse(self.store.delete(ref.sha256))
        self.assertEqual(self.store.total_bytes, 0)

    def test_counter_survives_restart(self):
        self.store.put_bytes(b"persist")
        again = BlobStore(os.path.join(self.tmp.name, "blobs"), 1024)
        self.assertEqual(again.total_bytes, 7)

    def test_integrity_check(self):
        ref = self.store.put_bytes(b"good")
        with open(ref.path, "wb") as fh:
            fh.write(b"evil!")
        with self.assertRaises(ValueError):
            self.store.get_bytes(ref.sha256)


if __name__ == "__main__":
    unittest.main()
