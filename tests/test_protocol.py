import unittest

from carbide.common import protocol
from carbide.common.protocol import (
    BlobReassembler, ProtocolError, iter_blob_chunks,
)
from carbide.common.util import sha256_hex


class ProtocolTest(unittest.TestCase):
    def test_envelope_roundtrip(self):
        msg = protocol.new_envelope("hello", sensor_id="s1")
        self.assertEqual(protocol.decode(protocol.encode(msg)), msg)

    def test_decode_rejects_garbage(self):
        with self.assertRaises(ProtocolError):
            protocol.decode(b"not json\n")
        with self.assertRaises(ProtocolError):
            protocol.decode(b"[1,2]\n")

    def test_tokens_equal(self):
        self.assertTrue(protocol.tokens_equal("abc", "abc"))
        self.assertFalse(protocol.tokens_equal("abc", "abd"))

    def test_chunk_reassembly(self):
        data = bytes(range(256)) * 500
        sha = sha256_hex(data)
        asm = BlobReassembler()
        result = None
        for seq, last, part in iter_blob_chunks(data, chunk_size=1000):
            result = asm.add(sha, seq, last, part)
        self.assertEqual(result, data)

    def test_reassembly_out_of_order_and_dup(self):
        data = b"z" * 5000
        sha = sha256_hex(data)
        chunks = list(iter_blob_chunks(data, chunk_size=1000))
        asm = BlobReassembler()
        self.assertIsNone(asm.add(sha, 2, False, chunks[2][2]))
        self.assertIsNone(asm.add(sha, 2, False, chunks[2][2]))  # dup
        self.assertIsNone(asm.add(sha, 0, False, chunks[0][2]))
        self.assertIsNone(asm.add(sha, 1, False, chunks[1][2]))
        self.assertIsNone(asm.add(sha, 3, False, chunks[3][2]))
        self.assertEqual(asm.add(sha, 4, True, chunks[4][2]), data)

    def test_reassembly_hash_mismatch(self):
        asm = BlobReassembler()
        with self.assertRaises(ProtocolError):
            asm.add("0" * 64, 0, True, b"tampered")


if __name__ == "__main__":
    unittest.main()
