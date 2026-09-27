import datetime
import unittest

from carbide.server.squid import SquidTailer, parse_line
from tests.fakes import FakeDatabase


LINE = ("1690000000.123     45 10.89.0.5 TCP_MISS/200 1234 GET "
        "http://example.com/x - HIER_DIRECT/93.184.216.34 text/html")
CONNECT_LINE = ("1690000001.000     10 10.89.0.6 TCP_TUNNEL/200 9999 CONNECT "
                "evil.test:443 - HIER_DIRECT/6.6.6.6 -")


class ParseTest(unittest.TestCase):
    def test_get_line(self):
        hit = parse_line(LINE)
        self.assertEqual(hit["client_ip"], "10.89.0.5")
        self.assertEqual(hit["method"], "GET")
        self.assertEqual(hit["url"], "http://example.com/x")
        self.assertEqual(hit["status"], 200)
        self.assertEqual(hit["bytes"], 1234)
        self.assertEqual(hit["mime"], "text/html")
        self.assertEqual(hit["at"], datetime.datetime.fromtimestamp(
            1690000000.123, datetime.timezone.utc))

    def test_connect_line(self):
        hit = parse_line(CONNECT_LINE)
        self.assertEqual(hit["method"], "CONNECT")
        self.assertEqual(hit["url"], "evil.test:443")
        self.assertEqual(hit["mime"], "")

    def test_garbage_rejected(self):
        self.assertIsNone(parse_line("hello world"))
        self.assertIsNone(parse_line(""))


class TailerTest(unittest.IsolatedAsyncioTestCase):
    async def test_attribution_prefers_open_session(self):
        db = FakeDatabase()
        await db.set_affinity("s1", "7.7.7.7", "c1", 22001, "pw",
                              "10.89.0.5")
        await db.ensure_session("old", "s1", "7.7.7.7")
        await db.set_session_end("old", datetime.datetime.now(
            datetime.timezone.utc), "done")
        await db.ensure_session("new", "s1", "7.7.7.7")
        tailer = SquidTailer(db, "/nonexistent")
        await tailer.handle_line(LINE)
        self.assertEqual(len(db.squid), 1)
        hit = db.squid[0]
        self.assertEqual(hit[0], "new")
        self.assertEqual(hit[1], "s1")
        self.assertEqual(hit[2], "10.89.0.5")

    async def test_unknown_ip_recorded_unattributed(self):
        db = FakeDatabase()
        tailer = SquidTailer(db, "/nonexistent")
        await tailer.handle_line(LINE)
        self.assertEqual(db.squid[0][0], "")
        self.assertEqual(db.squid[0][2], "10.89.0.5")


if __name__ == "__main__":
    unittest.main()
