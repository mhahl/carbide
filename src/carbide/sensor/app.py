"""carbide-sensor: SSH front door, D2 auth, per-connection session proxy and
recording, store-and-forward evidence shipping.
"""
import asyncio
import logging
import time

import asyncssh

from ..common.util import new_id
from .auth import AuthPolicy
from .proxy import bridge_shell_exec
from .recorder import Recorder
from .server_client import ServerError, ServerLink
from .sftp_forward import ForwardingSFTPServer
from .spool import Spool

log = logging.getLogger("carbide.sensor")


class _ConnCtx:
    def __init__(self, conn, session_id, recorder, auth):
        self.conn = conn
        self.session_id = session_id
        self.recorder = recorder
        self.auth = auth
        self.username = ""
        self.authed = False
        self.attacker_ip = ""
        self.endpoint = None
        self.endpoint_fresh = False
        self.container_client = None
        self.container_linked = False
        self.started = time.monotonic()
        self.last_activity = time.monotonic()
        self.channel_seq = 0
        self.lock = asyncio.Lock()
        self.watch_task = None


def _server_class(app):
    class HoneypotSSHServer(asyncssh.SSHServer):
        def connection_made(self, conn):
            app.conn_made(self, conn)

        def connection_lost(self, exc):
            app.conn_lost(self, exc)

        def begin_auth(self, username):
            return True

        def password_auth_supported(self):
            return app.auth_allowed(self)

        async def validate_password(self, username, password):
            return app.validate(self, username, password)

        def auth_completed(self):
            app.auth_completed(self)

        def connection_requested(self, *args):
            return False  # never forward TCP for attackers

        def server_requested(self, *args):
            return False

    return HoneypotSSHServer


class SensorApp:
    def __init__(self, cfg):
        self.cfg = cfg
        scfg = cfg.section("sensor")
        self.sensor_id = scfg["sensor_id"]
        self.spool = Spool(scfg["spool_dir"])
        self.link = ServerLink(
            scfg["server_host"], scfg["server_port"],
            self.sensor_id, scfg["token"], self.spool,
            request_timeout=scfg["request_timeout_s"],
            on_notify=self._handle_notify)
        acfg = cfg.section("auth")
        self.policy = AuthPolicy(acfg["passwords"],
                                 acfg["accept_probability"])
        self.max_attempts = acfg["max_attempts"]
        self.idle_timeout = scfg["session_idle_timeout_s"]
        self.max_time = scfg["session_max_time_s"]
        self.scp_max = cfg.get("quotas.session_max_bytes",
                               100 * 1024 * 1024)
        self._ctx_by_server: dict = {}
        self._ctx_by_conn: dict = {}
        self._ctx_by_session: dict = {}

    # -- SSHServer hooks -------------------------------------------------
    def conn_made(self, server, conn):
        peer = conn.get_extra_info("peername")
        ip = peer[0] if peer else "unknown"
        session_id = new_id()
        recorder = Recorder(self.spool, self.sensor_id, session_id,
                            wake=self.link.nudge)
        ctx = _ConnCtx(conn, session_id, recorder,
                       self.policy.for_connection())
        ctx.attacker_ip = ip
        self._ctx_by_server[server] = ctx
        self._ctx_by_conn[conn] = ctx
        self._ctx_by_session[session_id] = ctx
        ctx.watch_task = asyncio.create_task(self._watch(ctx))
        log.info("connection from %s session=%s", ip, session_id)

    def conn_lost(self, server, exc):
        ctx = self._ctx_by_server.pop(server, None)
        if ctx is None:
            return
        self._ctx_by_conn.pop(ctx.conn, None)
        self._ctx_by_session.pop(ctx.session_id, None)
        if ctx.watch_task is not None:
            ctx.watch_task.cancel()
        ctx.recorder.session_end("disconnect" if exc is None else
                                 f"error: {exc}")
        if ctx.container_client is not None:
            try:
                ctx.container_client.close()
            except Exception:
                pass
        log.info("closed session=%s (%s)", ctx.session_id,
                 "disconnect" if exc is None else exc)

    async def _handle_notify(self, msg: dict):
        """Server-pushed notifies (console actions)."""
        name = msg.get("name")
        if name != "kill_session":
            log.debug("ignoring unknown notify %s", name)
            return
        session_id = msg.get("session_id", "")
        ctx = self._ctx_by_session.get(session_id)
        if ctx is None:
            log.debug("kill_session %s: no such live session", session_id)
            return
        log.info("session=%s killed by operator", session_id)
        ctx.recorder.session_end("killed by operator")
        try:
            ctx.conn.close()
        except Exception:
            pass

    def auth_allowed(self, server) -> bool:
        ctx = self._ctx_by_server.get(server)
        return ctx is not None and ctx.auth.attempts < self.max_attempts

    def validate(self, server, username: str, password: str) -> bool:
        ctx = self._ctx_by_server.get(server)
        if ctx is None:
            return False
        accepted, matched = ctx.auth.attempt(username, password)
        ctx.recorder.auth_attempt(username, password, accepted, matched)
        if accepted:
            ctx.username = username
        log.info("auth %s user=%s matched_list=%s session=%s",
                 "accepted" if accepted else "rejected", username,
                 matched, ctx.session_id)
        return accepted

    def auth_completed(self, server):
        ctx = self._ctx_by_server.get(server)
        if ctx is None:
            return
        ctx.authed = True
        ctx.last_activity = time.monotonic()
        ctx.recorder.session_start(ctx.attacker_ip, ctx.username)

    async def _watch(self, ctx: _ConnCtx):
        try:
            while True:
                await asyncio.sleep(5)
                now = time.monotonic()
                if now - ctx.started > self.max_time:
                    reason = "max session time"
                    break
                if now - ctx.last_activity > self.idle_timeout:
                    reason = "idle timeout"
                    break
            else:
                return
            log.info("closing session=%s: %s", ctx.session_id, reason)
            ctx.recorder.session_end(reason)
            try:
                ctx.conn.close()
            except Exception:
                pass
        except asyncio.CancelledError:
            pass

    # -- channels --------------------------------------------------------
    async def handle_session(self, stdin, stdout, stderr):
        chan = stdin.channel
        conn = chan.get_connection()
        ctx = self._ctx_by_conn.get(conn)
        if ctx is None or not ctx.authed:
            try:
                chan.close()
            except Exception:
                pass
            return
        ctx.channel_seq += 1
        label = f"ch{ctx.channel_seq}"
        subsystem = chan.get_subsystem()
        try:
            endpoint = await self.container_endpoint(ctx)
            client = await self.container_client(ctx, endpoint)
        except ServerError as exc:
            log.warning("session=%s no container: %s", ctx.session_id, exc)
            try:
                stdout.write(b"upstream unavailable, try again later\r\n")
                chan.exit(1)
            except Exception:
                pass
            return
        except Exception as exc:
            log.warning("session=%s container connect failed: %s",
                        ctx.session_id, exc)
            try:
                stdout.write(b"upstream unavailable, try again later\r\n")
                chan.exit(1)
            except Exception:
                pass
            return
        if not ctx.container_linked:
            ctx.recorder.session_container(endpoint["container_id"],
                                           ctx.endpoint_fresh)
            ctx.container_linked = True
        if subsystem:
            # 'sftp' is served by sftp_factory; anything else is refused.
            log.info("session=%s refusing subsystem %r",
                     ctx.session_id, subsystem)
            try:
                chan.exit(1)
            except Exception:
                pass
            return
        await bridge_shell_exec(
            stdin, stdout, stderr, container_client=client,
            recorder=ctx.recorder, label=label,
            touch=lambda: setattr(ctx, "last_activity",
                                  time.monotonic()),
            scp_max_bytes=self.scp_max)

    async def container_endpoint(self, ctx: _ConnCtx) -> dict:
        async with ctx.lock:
            if ctx.endpoint is None:
                reply = await self.link.container_for(ctx.attacker_ip)
                ctx.endpoint = reply
                ctx.endpoint_fresh = bool(reply.get("fresh"))
            return ctx.endpoint

    async def container_client(self, ctx: _ConnCtx, endpoint: dict):
        async with ctx.lock:
            if ctx.container_client is None:
                ctx.container_client = await asyncssh.connect(
                    endpoint["ssh_host"], int(endpoint["ssh_port"]),
                    username=endpoint["ssh_user"],
                    password=endpoint["ssh_password"],
                    known_hosts=None, connect_timeout=10,
                    encoding=None)  # raw bytes end to end
            return ctx.container_client

    async def handle_sftp_factory(self, chan):
        """sftp_factory: build a forwarding SFTP server for one subsystem."""
        conn = chan.get_connection()
        ctx = self._ctx_by_conn.get(conn)
        if ctx is None or not ctx.authed:
            raise asyncssh.ChannelOpenError(1, "unavailable")
        ctx.channel_seq += 1
        label = f"ch{ctx.channel_seq}"
        try:
            endpoint = await self.container_endpoint(ctx)
            client = await self.container_client(ctx, endpoint)
        except Exception as exc:
            log.warning("session=%s sftp refused: %s", ctx.session_id, exc)
            raise asyncssh.ChannelOpenError(1, "unavailable")
        if not ctx.container_linked:
            ctx.recorder.session_container(endpoint["container_id"],
                                           ctx.endpoint_fresh)
            ctx.container_linked = True

        def evidence(name, data):
            ctx.recorder.evidence(f"{label}/{name}", data)

        def ops(line):
            ctx.last_activity = time.monotonic()
            ctx.recorder.transcript(label, "op", "sftp",
                                    (line + "\n").encode())

        try:
            sftp = await client.start_sftp_client()
        except Exception as exc:
            log.warning("session=%s sftp start failed: %s",
                        ctx.session_id, exc)
            raise asyncssh.ChannelOpenError(1, "unavailable")
        return ForwardingSFTPServer(chan, sftp, evidence, ops)

    # -- main ------------------------------------------------------------
    async def run(self):
        await self.link.start()
        scfg = self.cfg.section("sensor")
        listener = await asyncssh.create_server(
            _server_class(self), scfg["listen_addr"],
            int(scfg["listen_port"]),
            server_host_keys=[scfg["host_key_path"]],
            session_factory=self.handle_session,
            sftp_factory=self.handle_sftp_factory,
            encoding=None)  # raw bytes end to end
        log.info("sensor %s listening on %s:%s", self.sensor_id,
                 scfg["listen_addr"], scfg["listen_port"])
        try:
            await asyncio.Event().wait()
        finally:
            listener.close()
            await self.link.stop()
