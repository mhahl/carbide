"""Sensor-side link to carbide-server: authenticated JSON-lines TCP with a
background forwarder that drains the spool in order. Reconnects with backoff;
unacked records stay spooled and are redelivered (the server dedupes).
"""
import asyncio
import logging

from ..common import protocol

log = logging.getLogger("carbide.sensor.link")


class ServerError(Exception):
    pass


class ServerAuthError(ServerError):
    pass


class ServerLink:
    def __init__(self, host, port, sensor_id, token, spool,
                 request_timeout=10.0, on_notify=None):
        self._host = host
        self._port = port
        self._sensor_id = sensor_id
        self._token = token
        self._spool = spool
        self._timeout = request_timeout
        self._notify_handler = on_notify
        self._reader = None
        self._writer = None
        self._write_lock = asyncio.Lock()
        self._pending: dict[str, asyncio.Future] = {}
        self._wake = asyncio.Event()
        self._tasks: list[asyncio.Task] = []
        self._running = False
        self.ready = asyncio.Event()  # set while hello'd

    # -- lifecycle -----------------------------------------------------
    async def start(self):
        self._running = True
        self._tasks = [
            asyncio.create_task(self._run(), name="carbide-link"),
            asyncio.create_task(self._monitor(), name="carbide-spool-mon"),
        ]

    async def _monitor(self):
        """Log the spool depth while it is non-zero (backlog signal)."""
        try:
            while self._running:
                await asyncio.sleep(60)
                try:
                    depth = len(self._spool)
                except Exception:
                    continue
                if depth:
                    log.warning("spool backlog: %d records awaiting "
                                "forward", depth)
        except asyncio.CancelledError:
            pass

    async def stop(self):
        self._running = False
        self.nudge()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._drop_connection()

    def nudge(self):
        self._wake.set()

    @property
    def connected(self):
        return self.ready.is_set()

    # -- requests ------------------------------------------------------
    async def container_for(self, attacker_ip: str) -> dict:
        if not self.connected:
            raise ServerError("not connected to carbide-server")
        msg = protocol.new_envelope("container_for", attacker_ip=attacker_ip)
        reply = await self._request(msg)
        if not reply.get("ok"):
            raise ServerError(reply.get("error", "container_for failed"))
        return reply

    async def _request(self, msg: dict) -> dict:
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._pending[msg["id"]] = fut
        try:
            await self._send(msg)
            return await asyncio.wait_for(fut, self._timeout)
        except asyncio.TimeoutError:
            raise ServerError(f"request {msg['type']} timed out")
        finally:
            self._pending.pop(msg["id"], None)

    # -- connection loop -----------------------------------------------
    async def _run(self):
        backoff = 1.0
        while self._running:
            try:
                await self._connect_and_serve()
                backoff = 1.0
            except asyncio.CancelledError:
                raise
            except ServerAuthError:
                log.error("server rejected sensor credentials; retrying")
                await asyncio.sleep(5.0)
            except Exception as exc:  # reconnect on anything else
                log.warning("server link down: %s", exc)
                self._drop_connection()
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)

    async def _connect_and_serve(self):
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self._host, self._port), self._timeout)
        self._reader, self._writer = reader, writer
        reader_task = asyncio.create_task(self._read_loop())
        try:
            hello = protocol.new_envelope(
                "hello", sensor_id=self._sensor_id, token=self._token)
            reply = await self._request(hello)
            if not reply.get("ok"):
                raise ServerAuthError(reply.get("error", "hello rejected"))
            log.info("linked to carbide-server at %s:%s",
                     self._host, self._port)
            self.ready.set()
            try:
                forward_task = asyncio.create_task(self._forward_loop())
                done, pending = await asyncio.wait(
                    [reader_task, forward_task],
                    return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                for task in done:
                    exc = task.exception()
                    if exc is not None and not isinstance(
                            exc, asyncio.CancelledError):
                        raise exc
                raise ServerError("link closed")
            finally:
                self.ready.clear()
        finally:
            self._close_reader(reader_task)
            self._drop_connection()

    @staticmethod
    def _close_reader(reader_task):
        # A reader that already failed (e.g. EOF raced with shutdown)
        # must have its exception retrieved, else asyncio logs
        # "Task exception was never retrieved" at GC time.
        if not reader_task.done():
            reader_task.cancel()
        elif not reader_task.cancelled():
            reader_task.exception()

    def _drop_connection(self):
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(ServerError("link closed"))
        self._pending.clear()
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:
                pass
        self._reader = self._writer = None

    async def _send(self, msg: dict):
        if self._writer is None:
            raise ServerError("not connected")
        async with self._write_lock:
            self._writer.write(protocol.encode(msg))
            await self._writer.drain()

    async def _read_loop(self):
        while self._running:
            line = await self._reader.readline()
            if not line:
                raise ServerError("server closed connection")
            try:
                msg = protocol.decode(line)
            except protocol.ProtocolError as exc:
                log.warning("bad frame from server: %s", exc)
                continue
            if msg.get("type") == "notify":
                await self._on_notify(msg)
                continue
            reply_to = msg.get("in_reply_to")
            if reply_to and reply_to in self._pending:
                fut = self._pending.pop(reply_to)
                if not fut.done():
                    fut.set_result(msg)

    async def _on_notify(self, msg: dict):
        if self._notify_handler is None:
            log.debug("dropping notify %s (no handler)", msg.get("name"))
            return
        try:
            await self._notify_handler(msg)
        except Exception as exc:
            log.warning("notify %s failed: %s", msg.get("name"), exc)

    async def _forward_loop(self):
        while self._running:
            if not self.connected:
                await asyncio.sleep(0.2)
                continue
            work = self._spool.pending()
            if not work:
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), 1.0)
                except asyncio.TimeoutError:
                    pass
                continue
            slot, record = work[0]
            msg = protocol.new_envelope(
                "record", record_id=record["record_id"], record=record)
            try:
                reply = await self._request(msg)
            except ServerError as exc:
                log.warning("record forward failed: %s", exc)
                await asyncio.sleep(0.5)
                continue
            if reply.get("ok"):
                self._spool.ack(slot)
            else:
                log.error("server refused record: %s", reply.get("error"))
                self._spool.ack(slot)  # poison; drop to avoid a wedge
