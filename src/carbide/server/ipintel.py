"""Attacker IP intel: reverse DNS plus an unprivileged nmap profile per IP.

One scan per IP per cache TTL, serialized, with a timeout. Results land
in ip_intel for the console attacker view. The default profile is a
connect scan (no raw sockets, no container capabilities needed).
"""
import asyncio
import ipaddress
import json
import logging
import socket
import xml.etree.ElementTree as ET

log = logging.getLogger("carbide.server.ipintel")

_MAX_RAW_XML = 256 * 1024


class IPIntelError(Exception):
    pass


def parse_nmap_xml(xml_text: str) -> dict:
    """Pull rdns + open ports from nmap -oX output.

    Returns {"rdns": str, "ports": [{"port", "proto", "service",
    "version"}]}. Raises xml.etree.ElementTree.ParseError on garbage.
    """
    root = ET.fromstring(xml_text)
    rdns, ports = "", []
    host = root.find("host")
    if host is None:
        return {"rdns": rdns, "ports": ports}
    for elem in host.findall("hostnames/hostname"):
        if elem.get("type") == "PTR" and elem.get("name"):
            rdns = elem.get("name").rstrip(".")
            break
    else:
        first = host.find("hostnames/hostname")
        if first is not None and first.get("name"):
            rdns = first.get("name").rstrip(".")
    for port in host.findall("ports/port"):
        state = port.find("status")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        product = (service.get("product") or "") if service is not None \
            else ""
        version = (service.get("version") or "") if service is not None \
            else ""
        ports.append({
            "port": int(port.get("portid", 0)),
            "proto": port.get("protocol", "tcp"),
            "service": (service.get("name") or "") if service is not None
            else "",
            "version": f"{product} {version}".strip(),
        })
    ports.sort(key=lambda p: (p["proto"], p["port"]))
    return {"rdns": rdns, "ports": ports}


async def default_runner(args, ip: str, timeout_s: float):
    """Run nmap -oX - ; returns (returncode, stdout, stderr) as bytes."""
    proc = await asyncio.create_subprocess_exec(
        "nmap", *args, "-oX", "-", ip,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout_s)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        raise IPIntelError(f"nmap timed out after {timeout_s}s")
    return proc.returncode, out, err


async def default_resolver(ip: str) -> str:
    try:
        name, _, _ = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, ip), 10.0)
        return name.rstrip(".")
    except Exception:
        return ""


class IPIntel:
    def __init__(self, db, cfg, interval_s: float = 300.0, batch: int = 10,
                 runner=None, resolver=None):
        self._db = db
        self._args = list(cfg.get("ipintel.nmap_args",
                                  ["-sT", "--top-ports", "1000"]))
        self._cache_days = cfg.get("ipintel.cache_days", 7)
        self._timeout = cfg.get("ipintel.timeout_s", 300.0)
        self._interval = interval_s
        self._batch = batch
        self._runner = runner or default_runner
        self._resolver = resolver or default_resolver

    async def run_forever(self):
        log.info("ipintel started (pass every %ss)", self._interval)
        while True:
            try:
                done = await self.run_once()
                log.debug("ipintel pass: %d ips", done)
            except Exception as exc:
                log.warning("ipintel pass failed: %s", exc)
            await asyncio.sleep(self._interval)

    async def run_once(self, now=None) -> int:
        import datetime
        now = now or datetime.datetime.now(datetime.timezone.utc)
        cutoff = now - datetime.timedelta(days=self._cache_days)
        done = 0
        for ip in await self._db.ips_needing_scan(self._batch, cutoff):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                await self._db.save_ip_intel(ip, status="error",
                                             error="invalid ip address")
                done += 1
                continue
            try:
                await self._scan_one(ip)
            except FileNotFoundError:
                log.error("nmap binary missing; stopping pass")
                return done
            except IPIntelError as exc:
                log.warning("ipintel %s failed: %s", ip, exc)
                await self._db.save_ip_intel(ip, status="error",
                                             error=str(exc)[:500])
            done += 1
        return done

    async def _scan_one(self, ip: str):
        rdns = await self._resolver(ip)
        code, out, err = await self._runner(self._args, ip, self._timeout)
        text = out.decode("utf-8", "replace")
        if code != 0:
            detail = err.decode("utf-8", "replace").strip().splitlines()
            last = detail[-1][:200] if detail else ""
            hint = ""
            if "raw socket" in last.lower():
                hint = " (server container needs NET_RAW; re-run setup.sh)"
            raise IPIntelError(f"nmap exit {code}: {last}{hint}" if last
                               else f"nmap exit {code}{hint}")
        try:
            parsed = parse_nmap_xml(text)
        except ET.ParseError as exc:
            raise IPIntelError(f"unparseable nmap xml: {exc}")
        if not rdns:
            rdns = parsed["rdns"]
        await self._db.save_ip_intel(
            ip, rdns=rdns, status="ok",
            open_ports=json.dumps(parsed["ports"]),
            raw_xml=text[:_MAX_RAW_XML])
        log.info("ipintel %s: %d open ports", ip, len(parsed["ports"]))
