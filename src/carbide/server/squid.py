"""Squid access-log ingest (D3): tails the native-format log, parses one line
per request, and attributes each hit to a session by container IP.
"""
import asyncio
import datetime
import logging
import os
import re

log = logging.getLogger("carbide.server.squid")

# 1690000000.123     45 10.0.0.5 TCP_MISS/200 1234 GET http://x/ - HIER_DIRECT/1.2.3.4 text/html
_NATIVE = re.compile(
    r"^(?P<ts>\d+(?:\.\d+)?)\s+\d+\s+(?P<client>\S+)\s+"
    r"(?P<action>[A-Z_]+)/(?P<code>\d+)\s+(?P<size>\d+|TCP_REFRESH\w*|-)\s+"
    r"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+\S+\s+\S+\s*(?P<mime>\S+)?\s*$")


def parse_line(line: str):
    match = _NATIVE.match(line.strip())
    if not match:
        return None
    parts = match.groupdict()
    try:
        at = datetime.datetime.fromtimestamp(
            float(parts["ts"]), datetime.timezone.utc)
        size = int(parts["size"]) if parts["size"].isdigit() else 0
        mime = parts["mime"] or ""
        if mime == "-":
            mime = ""
        return {
            "at": at,
            "client_ip": parts["client"],
            "action": parts["action"],
            "status": int(parts["code"]),
            "bytes": size,
            "method": parts["method"],
            "url": parts["url"],
            "mime": mime,
        }
    except (ValueError, TypeError):
        return None


class SquidTailer:
    """Follows the log like tail -F (survives rotation) and records hits."""

    def __init__(self, db, log_path: str, poll_s: float = 1.0):
        self._db = db
        self._path = log_path
        self._poll = poll_s
        self._running = False
        self._missing_warned = False

    async def run_forever(self):
        self._running = True
        log.info("tailing squid log %s", self._path)
        fh = None
        inode = None
        try:
            while self._running:
                try:
                    if fh is None:
                        fh, inode = self._open_end()
                    if fh is None:
                        if not self._missing_warned:
                            log.warning("squid log %s not found; waiting",
                                        self._path)
                            self._missing_warned = True
                        else:
                            log.debug("squid log %s still missing",
                                      self._path)
                        await asyncio.sleep(self._poll)
                        continue
                    line = fh.readline()
                    if line:
                        await self.handle_line(line)
                        continue
                    if self._rotated(inode):
                        log.info("squid log rotated; reopening %s",
                                 self._path)
                        fh.close()
                        fh, inode = None, None
                        continue
                    await asyncio.sleep(self._poll)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log.warning("squid tail error: %s", exc)
                    await asyncio.sleep(self._poll)
        finally:
            if fh is not None:
                fh.close()

    def stop(self):
        self._running = False

    def _open_end(self):
        try:
            stat = os.stat(self._path)
            fh = open(self._path, errors="replace")
            fh.seek(0, os.SEEK_END)
            self._missing_warned = False
            return fh, stat.st_ino
        except OSError:
            return None, None

    def _rotated(self, inode) -> bool:
        try:
            return os.stat(self._path).st_ino != inode
        except OSError:
            return True

    async def handle_line(self, line: str):
        hit = parse_line(line)
        if hit is None:
            log.debug("unparseable squid line: %.160s", line.strip())
            return
        aff = await self._db.get_affinity_by_container_ip(hit["client_ip"])
        session_id = ""
        sensor_id = ""
        if aff is not None:
            sensor_id = aff["sensor_id"]
            row = await self._db.latest_open_session(
                aff["sensor_id"], aff["attacker_ip"])
            if row is None:
                row = await self._db.latest_session(
                    aff["sensor_id"], aff["attacker_ip"])
            if row is not None:
                session_id = row[0]
        else:
            log.debug("squid hit from unattributed ip %s: %s %s",
                      hit["client_ip"], hit["method"], hit["url"])
        if session_id:
            log.debug("squid hit %s %s -> session %s",
                      hit["method"], hit["url"], session_id)
        await self._db.add_squid_hit(
            session_id, sensor_id, hit["client_ip"], hit["at"],
            hit["method"], hit["url"], hit["status"], hit["bytes"],
            hit["mime"])
