"""Tests for carbide.server.ipintel (fake runner; PgCluster for queue)."""
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

from carbide.common.config import validate
from carbide.server.db import Database
from carbide.server import ipintel as ipintel_mod
from carbide.server.ipintel import (IPIntel, IPIntelError,
                                    default_geo_lookup, parse_nmap_xml)
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

        async def geo(ip):
            self.geo_calls.append(ip)
            return dict(self.geo_result)

        self.geo_calls = []
        self.geo_result = {}
        self.result = (0, NMAP_XML.encode(), b"")
        self.intel = IPIntel(self.db, make_cfg(), runner=runner,
                             resolver=resolver, geo=geo)

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

    async def test_geo_saved_with_scan(self):
        await self.db.ensure_session("s1", "s1", "1.2.3.4")
        self.geo_result = {"country_code": "NL", "country": "Netherlands",
                           "city": "Amsterdam", "org": "Example ISP"}
        self.assertEqual(await self.intel.run_once(), 1)
        self.assertEqual(self.geo_calls, ["1.2.3.4"])
        row = await self.db.get_ip_intel("1.2.3.4")
        self.assertEqual(row["status"], "ok")
        self.assertEqual(
            (row["country_code"], row["country"], row["city"], row["org"]),
            ("NL", "Netherlands", "Amsterdam", "Example ISP"))

    async def test_geo_and_rdns_kept_on_nmap_failure(self):
        await self.db.ensure_session("s1", "s1", "5.6.7.8")
        self.geo_result = {"country_code": "DE", "country": "Germany",
                           "city": "Berlin", "org": "Example GmbH"}
        self.result = (1, b"", b"FAIL: no route")
        self.assertEqual(await self.intel.run_once(), 1)
        row = await self.db.get_ip_intel("5.6.7.8")
        self.assertEqual(row["status"], "error")
        self.assertIn("nmap exit 1", row["error"])
        self.assertEqual(row["rdns"], "ptr.example.com")
        self.assertEqual(
            (row["country_code"], row["city"]), ("DE", "Berlin"))

    async def test_geo_disabled_skips_lookup(self):
        await self.db.ensure_session("s1", "s1", "1.2.3.4")
        cfg = make_cfg(ipintel={"geo_enabled": False})
        intel = IPIntel(self.db, cfg, runner=self.intel._runner,
                        resolver=self.intel._resolver,
                        geo=self.intel._geo)
        self.assertEqual(await intel.run_once(), 1)
        self.assertEqual(self.geo_calls, [])
        row = await self.db.get_ip_intel("1.2.3.4")
        self.assertEqual(row["country_code"], "")


class GeoLookupTest(unittest.IsolatedAsyncioTestCase):
    async def test_private_and_invalid_skip_network(self):
        for ip in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "::1",
                   "169.254.1.1", "224.0.0.1", "not-an-ip", ""):
            self.assertEqual(await default_geo_lookup(ip), {}, ip)

    async def test_http_success_and_fail(self):
        from aiohttp import web

        async def handler(request):
            if request.match_info["ip"] == "9.9.9.9":
                return web.json_response({
                    "status": "success", "country": "Netherlands",
                    "countryCode": "NL", "city": "Amsterdam",
                    "org": "Example ISP", "query": "9.9.9.9"})
            return web.json_response({"status": "fail",
                                      "message": "reserved range"})

        app = web.Application()
        app.router.add_get("/json/{ip}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        self.addAsyncCleanup(runner.cleanup)
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        _host, port = runner.addresses[0]
        with mock.patch.object(
                ipintel_mod, "_GEO_URL",
                f"http://127.0.0.1:{port}/json/{{ip}}"):
            out = await default_geo_lookup("9.9.9.9")
            self.assertEqual(
                out, {"country_code": "NL", "country": "Netherlands",
                      "city": "Amsterdam", "org": "Example ISP"})
            self.assertEqual(
                await default_geo_lookup("8.8.8.8"), {})


if __name__ == "__main__":
    unittest.main()
