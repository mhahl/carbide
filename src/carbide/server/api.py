"""carbide-server control API: authenticated JSON-lines TCP.

Sensors authenticate with one shared token and then (a) resolve attacker IPs
to containers and (b) stream evidence records. Sensor input is untrusted: the
connection's sensor identity overrides anything in the records, every record
applies at most once, and malformed records are refused (the sensor drops
refused records so one poison record cannot wedge the spool).
"""
import asyncio
import datetime
import logging

from ..common import protocol
from ..common.protocol import BlobReassembler
from ..common.util import b64d
from .podman_wrap import PodmanError

log = logging.getLogger("carbide.server.api")


class RecordError(Exception):
    pass


def parse_at(value):
    try:
        return datetime.datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return datetime.datetime.now(datetime.timezone.utc)


def _need_str(record: dict, key: str, limit: int = 4096) -> str:
    value = record.get(key)
    if not isinstance(value, str) or len(value) > limit:
        raise RecordError(f"bad {key}")
    return value


class ServerAPI:
    def __init__(self, db, pool, forensics, blobstore, cfg, bus=None):
        scfg = cfg.section("server")
        self._addr = scfg["api_addr"]
        self._port = scfg["api_port"]
        self._sensor_token = scfg["sensor_token"]
        self._db = db
        self._pool = pool
        self._forensics = forensics
        self._blobs = blobstore
        self._bus = bus
        self._session_max = cfg.get("quotas.session_max_bytes",
                                    100 * 1024 * 1024)
        self._asm = BlobReassembler()
        self._server = None
        self._handlers = set()
        self._links: dict = {}  # sensor_id -> set of writers

    def _emit(self, event: str, **data):
        if self._bus is not None:
            self._bus.publish(event, data)

    def live_sensors(self) -> dict:
        """sensor_id -> number of open links (console sensor state)."""
        return {sid: len(writers) for sid, writers in self._links.items()
                if writers}

    async def notify_sensor(self, sensor_id: str, name: str,
                            **fields) -> bool:
        """Push a server->sensor notify; True if any link took it."""
        writers = set(self._links.get(sensor_id, set()))
        if not writers:
            return False
        msg = protocol.new_envelope("notify", name=name, **fields)
        frame = protocol.encode(msg)
        delivered = False
        for writer in writers:
            try:
                writer.write(frame)
                await writer.drain()
                delivered = True
            except Exception:
                self._link_drop(sensor_id, writer)
        log.debug("notify %s -> %s: %s", sensor_id, name,
                  "delivered" if delivered else "all links dead")
        return delivered

    def _link_add(self, sensor_id: str, writer):
        self._links.setdefault(sensor_id, set()).add(writer)

    def _link_drop(self, sensor_id: str, writer):
        writers = self._links.get(sensor_id)
        if writers is not None:
            writers.discard(writer)
            if not writers:
                del self._links[sensor_id]

    async def run(self):
        self._server = await asyncio.start_server(
            self._handle, self._addr, self._port)
        log.info("server api on %s:%s", self._addr, self._port)
        async with self._server:
            try:
                await self._server.serve_forever()
            finally:
                # Drain per-connection handlers before returning: a handler
                # using the database after close() segfaults the C accel.
                handlers = list(self._handlers)
                for task in handlers:
                    task.cancel()
                if handlers:
                    await asyncio.gather(*handlers,
                                         return_exceptions=True)

    async def _handle(self, reader, writer):
        task = asyncio.current_task()
        self._handlers.add(task)
        try:
            await self._serve_connection(reader, writer)
        finally:
            self._handlers.discard(task)

    async def _serve_connection(self, reader, writer):
        sensor_id = None
        peer = writer.get_extra_info("peername")
        log.debug("api connection from %s", peer)
        try:
            while True:
                line = await reader.readline()
                if not line:
                    return
                try:
                    msg = protocol.decode(line)
                except protocol.ProtocolError:
                    continue
                req_id = msg.get("id")
                if not req_id:
                    continue
                mtype = msg.get("type")
                try:
                    if mtype == "hello":
                        sensor_id = await self._hello(msg)
                        self._link_add(sensor_id, writer)
                        reply = protocol.new_reply(req_id, ok=True)
                    elif sensor_id is None:
                        reply = protocol.new_reply(
                            req_id, ok=False, error="hello first")
                    elif mtype == "ping":
                        reply = protocol.new_reply(req_id, ok=True)
                    elif mtype == "container_for":
                        endpoint = await self._container_for(sensor_id, msg)
                        reply = protocol.new_reply(req_id, ok=True,
                                                   **endpoint)
                    elif mtype == "record":
                        await self._record(sensor_id, msg)
                        reply = protocol.new_reply(req_id, ok=True)
                    else:
                        reply = protocol.new_reply(
                            req_id, ok=False, error="unknown type")
                except RecordError as exc:
                    log.debug("refusing %s from %s: %s",
                              mtype, sensor_id or peer, exc)
                    reply = protocol.new_reply(
                        req_id, ok=False, error=str(exc))
                except PodmanError as exc:
                    log.warning("podman failure serving %s from %s: %s",
                                mtype, sensor_id or peer, exc)
                    reply = protocol.new_reply(
                        req_id, ok=False, error=str(exc))
                except Exception as exc:  # never drop the link on one msg
                    log.warning("request failed: %s", exc)
                    reply = protocol.new_reply(
                        req_id, ok=False, error="internal error")
                writer.write(protocol.encode(reply))
                await writer.drain()
                if mtype == "hello" and not reply.get("ok"):
                    log.warning("sensor link rejected from %s: %s",
                                peer, reply.get("error"))
                    return
                if sensor_id is None and mtype != "hello":
                    log.debug("dropping unauthenticated %s from %s",
                              mtype, peer)
                    return
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            if sensor_id is not None:
                self._link_drop(sensor_id, writer)
            try:
                writer.close()
            except Exception:
                pass
            log.debug("api connection from %s closed", peer)

    async def _hello(self, msg: dict) -> str:
        sensor_id = msg.get("sensor_id")
        token = msg.get("token")
        if not isinstance(sensor_id, str) or not sensor_id or \
                len(sensor_id) > 128:
            raise RecordError("bad sensor_id")
        if not isinstance(token, str) or \
                not protocol.tokens_equal(token, self._sensor_token):
            raise RecordError("bad sensor credentials")
        await self._db.note_sensor(sensor_id)
        log.info("sensor %s linked", sensor_id)
        return sensor_id

    async def _container_for(self, sensor_id: str, msg: dict) -> dict:
        ip = msg.get("attacker_ip")
        if not isinstance(ip, str) or not ip or len(ip) > 64:
            raise RecordError("bad attacker_ip")
        endpoint = await self._pool.container_for(sensor_id, ip)
        log.debug("container_for %s %s -> %s (fresh=%s)", sensor_id, ip,
                  endpoint["container_id"][:12], endpoint["fresh"])
        return endpoint

    async def _record(self, sensor_id: str, msg: dict):
        record = msg.get("record")
        if not isinstance(record, dict):
            raise RecordError("record must be an object")
        record_id = record.get("record_id")
        kind = record.get("kind")
        session_id = record.get("session_id")
        if not all(isinstance(v, str) and v for v in
                   (record_id, kind, session_id)):
            raise RecordError("record needs record_id/kind/session_id")
        if len(record_id) > 128 or len(session_id) > 128:
            raise RecordError("record/session id too long")
        if not await self._db.claim_record(record_id):
            log.debug("duplicate record %s ignored (session %s)",
                      record_id, session_id)
            return  # duplicate delivery; already applied
        handler = {
            protocol.KIND_SESSION_START: self._r_session_start,
            protocol.KIND_SESSION_CONTAINER: self._r_session_container,
            protocol.KIND_SESSION_END: self._r_session_end,
            protocol.KIND_AUTH_ATTEMPT: self._r_auth,
            protocol.KIND_TRANSCRIPT: self._r_transcript,
            protocol.KIND_BLOB_META: self._r_blob_meta,
            protocol.KIND_BLOB_CHUNK: self._r_blob_chunk,
        }.get(kind)
        if handler is None:
            raise RecordError(f"unknown kind {kind}")
        await handler(sensor_id, session_id, record)
        log.debug("record %s (%s) for session %s applied",
                  record_id, kind, session_id)

    async def _r_session_start(self, sensor_id, session_id, record):
        ip = _need_str(record, "attacker_ip", 64)
        username = record.get("username", "")
        if not isinstance(username, str) or len(username) > 256:
            raise RecordError("bad username")
        await self._db.ensure_session(session_id, sensor_id, ip)
        await self._db.set_session_started(
            session_id, username, parse_at(record.get("at")), ip)
        await self._pool.session_started(sensor_id, ip)
        log.info("session %s started: sensor=%s ip=%s user=%s",
                 session_id, sensor_id, ip, username or "-")
        self._emit("session.started", session_id=session_id,
                   sensor_id=sensor_id, attacker_ip=ip,
                   username=username)

    async def _r_session_container(self, sensor_id, session_id, record):
        cid = _need_str(record, "container_id", 128)
        fresh = bool(record.get("fresh"))
        await self._db.ensure_session(session_id, sensor_id, "")
        await self._db.set_session_container(session_id, cid, fresh)

    async def _r_session_end(self, sensor_id, session_id, record):
        reason = record.get("reason", "")
        if not isinstance(reason, str) or len(reason) > 512:
            raise RecordError("bad reason")
        await self._db.ensure_session(session_id, sensor_id, "")
        await self._db.set_session_end(
            session_id, parse_at(record.get("at")), reason)
        session = await self._db.get_session(session_id)
        if session is None:
            return
        ip, container_id = session[2], session[4]
        if ip:
            await self._pool.session_ended(sensor_id, ip)
        log.info("session %s ended: sensor=%s ip=%s reason=%s",
                 session_id, sensor_id, ip or "-", reason or "-")
        self._emit("session.ended", session_id=session_id,
                   sensor_id=sensor_id, attacker_ip=ip or "",
                   reason=reason or "")
        if container_id:
            asyncio.create_task(self._collect(
                sensor_id, ip, session_id, container_id, reason))

    async def _collect(self, sensor_id, ip, session_id, container_id,
                       reason):
        log.debug("starting forensics for session %s (container %s)",
                  session_id, container_id[:12])
        try:
            summary = await self._forensics.collect(
                sensor_id=sensor_id, attacker_ip=ip, session_id=session_id,
                container_id=container_id, reason=reason or "session end")
            log.info("forensics for %s: %d changes, %d warnings",
                     session_id, summary["changes"], len(summary["warnings"]))
            self._emit("forensics.ready", session_id=session_id,
                       changes=summary["changes"],
                       warnings=len(summary["warnings"]))
        except Exception as exc:
            log.warning("forensics for %s failed: %s", session_id, exc)

    async def _r_auth(self, sensor_id, session_id, record):
        username = record.get("username", "")
        password = record.get("password", "")
        if not isinstance(username, str) or len(username) > 256:
            raise RecordError("bad username")
        if not isinstance(password, str) or len(password) > 1024:
            raise RecordError("bad password")
        await self._db.ensure_session(session_id, sensor_id, "")
        await self._db.add_auth_attempt(
            session_id, sensor_id, username, password,
            bool(record.get("accepted")), bool(record.get("matched_list")),
            parse_at(record.get("at")))
        # Never log the password: usernames and outcomes only.
        log.debug("auth attempt session=%s user=%s accepted=%s listed=%s",
                  session_id, username or "-",
                  bool(record.get("accepted")),
                  bool(record.get("matched_list")))
        self._emit("auth.attempt", session_id=session_id,
                   sensor_id=sensor_id, username=username,
                   accepted=bool(record.get("accepted")))

    async def _over_quota(self, session_id, extra: int) -> bool:
        try:
            used = await self._db.session_byte_count(session_id)
        except Exception:
            return False
        if used + extra > self._session_max:
            await self._db.set_session_over_quota(session_id)
            log.debug("session %s over quota; dropping %d bytes",
                      session_id, extra)
            return True
        return False

    async def _r_transcript(self, sensor_id, session_id, record):
        for key in ("channel", "direction", "stream"):
            _need_str(record, key, 64)
        seq = record.get("seq", 0)
        if not isinstance(seq, int) or seq < 0:
            raise RecordError("bad seq")
        try:
            data = b64d(record.get("data_b64", ""))
        except Exception:
            raise RecordError("bad data_b64")
        await self._db.ensure_session(session_id, sensor_id, "")
        if await self._over_quota(session_id, len(data)):
            return
        await self._db.add_transcript(
            session_id, record["channel"], record["direction"],
            record["stream"], seq, data, parse_at(record.get("at")))
        self._emit("transcript.chunk", session_id=session_id,
                   channel=record["channel"],
                   direction=record["direction"], bytes=len(data))

    async def _r_blob_meta(self, sensor_id, session_id, record):
        _need_str(record, "blob_sha", 64)
        _need_str(record, "name", 1024)
        size = record.get("size", 0)
        if not isinstance(size, int) or size < 0:
            raise RecordError("bad size")
        await self._db.ensure_session(session_id, sensor_id, "")

    async def _r_blob_chunk(self, sensor_id, session_id, record):
        sha = _need_str(record, "blob_sha", 64)
        name = _need_str(record, "name", 1024)
        seq = record.get("seq", 0)
        last = record.get("last", False)
        if not isinstance(seq, int) or seq < 0 or not isinstance(last, bool):
            raise RecordError("bad chunk framing")
        try:
            data = b64d(record.get("data_b64", ""))
        except Exception:
            raise RecordError("bad data_b64")
        await self._db.ensure_session(session_id, sensor_id, "")
        try:
            blob = self._asm.add(sha, seq, last, data)
        except protocol.ProtocolError as exc:
            self._asm.discard(sha)
            raise RecordError(str(exc))
        if blob is None:
            return
        at = parse_at(record.get("at"))
        if await self._over_quota(session_id, len(blob)):
            await self._db.add_session_file(session_id, name, None,
                                            len(blob), at)
            log.info("file %s for session %s dropped (session over quota)",
                     name, session_id)
            return
        try:
            ref = self._blobs.put_bytes(blob)
        except Exception:
            await self._db.set_session_over_quota(session_id)
            await self._db.add_session_file(session_id, name, None,
                                            len(blob), at)
            log.warning("blob store full; file %s for session %s recorded "
                        "without content", name, session_id)
            return
        await self._db.add_blob(ref.sha256, ref.path, ref.size)
        await self._db.add_session_file(session_id, name, ref.sha256,
                                        ref.size, at)
        log.info("stored file %s (%d bytes) for session %s",
                 name, ref.size, session_id)
        self._emit("file.stored", session_id=session_id, name=name,
                   size=ref.size, sha256=ref.sha256)
