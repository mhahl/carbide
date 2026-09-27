import os
import tempfile
import unittest

from carbide.sensor.spool import Spool


class SpoolTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.spool = Spool(os.path.join(self.tmp.name, "spool"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_append_pending_ack(self):
        slot, rid = self.spool.append({"kind": "x", "n": 1})
        self.assertEqual(len(self.spool), 1)
        pending = self.spool.pending()
        self.assertEqual(pending[0][0], slot)
        self.assertEqual(pending[0][1]["record_id"], rid)
        self.assertEqual(pending[0][1]["n"], 1)
        self.spool.ack(slot)
        self.assertEqual(len(self.spool), 0)

    def test_survives_reopen(self):
        _slot, rid = self.spool.append({"kind": "y"})
        again = Spool(os.path.join(self.tmp.name, "spool"))
        self.assertEqual(len(again), 1)
        self.assertEqual(again.pending()[0][1]["record_id"], rid)

    def test_ack_missing_is_fine(self):
        self.spool.ack("nope.json")

    def test_skips_tmp_files(self):
        with open(os.path.join(self.tmp.name, "spool", "x.tmp"), "w") as fh:
            fh.write("half")
        self.assertEqual(len(self.spool), 0)


if __name__ == "__main__":
    unittest.main()
