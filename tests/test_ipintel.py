"""Tests for carbide.server.ipintel (fake runner; PgCluster for queue)."""
import unittest
import xml.etree.ElementTree as ET

from carbide.common.config import validate
from carbide.server.db import Database
from carbide.server.ipintel import IPIntel, IPIntelError, parse_nmap_xml
from tests.pgcluster import PgCluster, postgres_available

requires_pg = unittest.skipUnless(postgres_available(),
                                  "postgres binaries/user missing")

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up" reason="conn-refused"/>
<address addr="1.2.3.4" addrtype="ipv4"/>
<hostnames><hostname name="evil.example.com" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><status state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="8.9"/></port>
<port protocol="tcp" portid="80"><status state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.24"/></port>
<port protocol="tcp" portid="443"><status state="filtered" reason="no-response"/>
<service name="https"/></port>
</ports>
</host>
</nmaprun>
"""


def make_cfg(**over):
    raw = {
        "role": "server",
        "server": {"sensor_token": "tok", "db_dsn": "x",
                   "blob_dir": "y"},
        "podman": {"image": "img"},
    }
    for section, values in over.items():
        raw.setdefault(section, {}).update(values)
    return validate(raw)


class ParseTest(unittest.TestCase):
    def test_open_ports_and_rdns(self):
        out = parse_nmap_xml(NMAP_XML)
        self.assertEqual(out["rdns"], "evil.example.com")
        self.assertEqual(out["ports"], [
            {"port": 22, "proto": "tcp", "service": "ssh",
             "version": "OpenSSH 8.9"},
            {"port": 80, "proto": "tcp", "service": "http",
             "version": "nginx 1.24"},
        ])

    def test_no_host_and_garbage(self):
        out = parse_nmap_xml('<?xml version="1.0"?><nmaprun/>')
        self.assertEqual(out, {"rdns": "", "ports": []})
        with self.assertRaises(ET.ParseError):
            parse_nmap_xml("not xml at all <<<")


@requires_pg
class IntelQueueTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import asyncio
        loop = asyncio.get_running_loop()
        self.cluster = PgCluster()
        dsn = await loop.run_in_executor(None, self.cluster.start)
        self.db = Database(dsn)
        await self.db.connect()
        self.calls = []

        async def runner(args, ip, timeout):
            self.calls.append((list(args), ip, timeout))
            return self.result

        async def resolver(ip):
            return "ptr.example.com"

        self.result = (0, NMAP_XML.encode(), b"")
        self.intel = IPIntel(self.db, make_cfg(), runner=runner,
                             resolver=resolver)

    async def asyncTearDown(self):
        import asyncio
        await self.db.close()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.cluster.stop)

    async def test_new_ip_scanned_once(self):
        await self.db.ensure_session("s1", "s1", "1.2.3.4")
        self.assertEqual(await self.intel.run_once(), 1)
        self.assertEqual(len(self.calls), 1)
        args, ip, timeout = self.calls[0]
        self.assertEqual(ip, "1.2.3.4")
        self.assertIn("-sT", args)
        row = await self.db.get_ip_intel("1.2.3.4")
        self.assertEqual(row["status"], "ok")
        self.assertEqual(row["rdns"], "ptr.example.com")
        self.assertIn('"port": 22', row["open_ports"])
        self.assertIn("nmaprun", row["raw_xml"])
        # second pass: cache hit, no rescan
        self.assertEqual(await self.intel.run_once(), 0)
        self.assertEqual(len(self.calls), 1)

    async def test_invalid_ip_and_failures(self):
        await self.db.ensure_session("s1", "s1", "not-an-ip")
        await self.db.ensure_session("s2", "s1", "5.6.7.8")
        self.result = (1, b"", b"mass_dns: warning: blah\nFAIL: no route")
        self.assertEqual(await self.intel.run_once(), 2)
        bad = await self.db.get_ip_intel("not-an-ip")
        self.assertEqual((bad["status"], bad["error"]),
                         ("error", "invalid ip address"))
        failed = await self.db.get_ip_intel("5.6.7.8")
        self.assertEqual(failed["status"], "error")
        self.assertIn("nmap exit 1", failed["error"])

    async def test_raw_socket_failure_names_fix(self):
        await self.db.ensure_session("s1", "s1", "1.2.3.4")
        self.result = (1, b"",
                       b"Couldn't open a raw socket. "
                       b"Error: Operation not permitted (1)")
        self.assertEqual(await self.intel.run_once(), 1)
        row = await self.db.get_ip_intel("1.2.3.4")
        self.assertEqual(row["status"], "error")
        self.assertIn("nmap exit 1", row["error"])
        self.assertIn("NET_RAW", row["error"])

    async def test_missing_binary_stops_pass(self):
        await self.db.ensure_session("s1", "s1", "1.2.3.4")

        async def missing(args, ip, timeout):
            raise FileNotFoundError("nmap")

        self.intel._runner = missing
        self.assertEqual(await self.intel.run_once(), 0)
        self.assertIsNone(await self.db.get_ip_intel("1.2.3.4"))


if __name__ == "__main__":
    unittest.main()
