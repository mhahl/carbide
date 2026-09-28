"""Affinity pool: per-sensor IP->container mapping with a pre-warmed fresh
pool, keep-warm stops, and port allocation. All blocking Podman calls run in
an executor; ``podman`` here is any object with the PodmanWrapper surface
(real or fake).
"""
import asyncio
import logging
import secrets

from .podman_wrap import PodmanError

log = logging.getLogger("carbide.server.pool")

REF_NAME = "carbide-ref"


def new_password() -> str:
    return secrets.token_hex(12)


class Pool:
    def __init__(self, podman, db, cfg):
        self._pod = podman
        self._db = db
        pcfg = cfg.section("podman")
        acfg = cfg.section("affinity")
        self._image = pcfg["image"]
        self._network = pcfg["network"]
        self._user = pcfg["container_user"]
        self._memory = pcfg["memory_mb"]
        self._pids = pcfg["pids_limit"]
        self._pool_size = pcfg["pool_size"]
        self._port_start = pcfg["port_range_start"]
        self._port_end = pcfg["port_range_end"]
        self._ssh_host = pcfg["ssh_host"] or cfg.get("server.api_addr")
        self._keep_warm_s = acfg["keep_warm_minutes"] * 60
        self._squid_mode = cfg.get("squid.mode", "transparent")
        self._squid_proxy = cfg.get("squid.explicit_proxy", "")
        self._squid_enabled = cfg.get("squid.enabled", True)
        self._used_ports: set[int] = set()
        self._fresh: list[dict] = []  # {container_id, port, password}
        self._refcounts: dict[tuple[str, str], int] = {}
        self._warm_tasks: dict[tuple[str, str], asyncio.Task] = {}
        self._lock = asyncio.Lock()

    async def run_sync(self, fn, *args, **kwargs):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: fn(*args, **kwargs))

    # -- startup ---------------------------------------------------------
    async def start(self):
        log.info("pool starting (image=%s network=%s ports=%d-%d fresh=%d)",
                 self._image, self._network, self._port_start,
                 self._port_end, self._pool_size)
        await self.run_sync(self._pod.connect)
        await self.run_sync(self._pod.ensure_network, self._network)
        self._used_ports = set(await self._db.ports_in_use())
        capacity = self._port_end - self._port_start + 1
        if capacity <= 0:
            raise PodmanError("podman port range is empty")
        await self._reconcile()
        await self._ensure_reference()
        await self._refill()
        log.info("pool ready (%d fresh containers)", len(self._fresh))

    async def _reconcile(self):
        kept, dropped, strays = 0, 0, 0
        for aff in await self._db.list_affinities():
            cid = aff["container_id"]
            if not await self.run_sync(self._pod.exists, cid):
                log.warning("affinity %s/%s lost its container; dropping",
                            aff["sensor_id"], aff["attacker_ip"])
                await self._db.delete_affinity(aff["sensor_id"],
                                               aff["attacker_ip"])
                self._used_ports.discard(aff["ssh_port"])
                dropped += 1
            else:
                kept += 1
        known = {a["container_id"]
                 for a in await self._db.list_affinities()}
        for container in await self.run_sync(self._pod.list_carbide):
            cid = container.id
            name = ""
            try:
                name = container.name or ""
            except Exception:
                pass
            if cid in known or name == REF_NAME:
                continue
            log.warning("removing stray carbide container %s", cid[:12])
            await self.run_sync(self._pod.remove, cid)
            strays += 1
        log.debug("reconcile: %d affinities kept, %d dropped, %d strays "
                  "removed", kept, dropped, strays)

    async def _ensure_reference(self):
        exists = await self.run_sync(self._pod.exists, REF_NAME)
        if not exists:
            port = self._alloc_port()
            try:
                await self.run_sync(
                    self._pod.create_container, REF_NAME, self._image,
                    self._user, port, self._network,
                    {"CARBIDE_PASSWORD": new_password()},
                    self._memory, self._pids)
            finally:
                self._free_port(port)
            log.info("created reference container %s", REF_NAME)
        else:
            log.debug("reference container %s present", REF_NAME)

    def reference_id(self) -> str:
        return REF_NAME

    # -- ports -------------------------------------------------------------
    def _alloc_port(self) -> int:
        for port in range(self._port_start, self._port_end + 1):
            if port not in self._used_ports:
                self._used_ports.add(port)
                return port
        raise PodmanError("podman host-port range exhausted")

    def _free_port(self, port: int):
        self._used_ports.discard(port)

    # -- fresh pool ----------------------------------------------------------
    def _env(self, password: str) -> dict:
        env = {"CARBIDE_PASSWORD": password}
        if self._squid_enabled and self._squid_mode == "explicit":
            env["HTTP_PROXY"] = self._squid_proxy
            env["HTTPS_PROXY"] = self._squid_proxy
            env["http_proxy"] = self._squid_proxy
            env["https_proxy"] = self._squid_proxy
        return env

    async def _create_fresh(self) -> dict:
        name = f"carbide-fresh-{secrets.token_hex(4)}"
        password = new_password()
        port = self._alloc_port()
        try:
            cid = await self.run_sync(
                self._pod.create_container, name, self._image, self._user,
                port, self._network, self._env(password),
                self._memory, self._pids)
        except Exception:
            self._free_port(port)
            raise
        log.info("created fresh container %s (port %d)", cid[:12], port)
        return {"container_id": cid, "port": port, "password": password}

    async def _refill(self):
        async with self._lock:
            while len(self._fresh) < self._pool_size:
                try:
                    self._fresh.append(await self._create_fresh())
                except Exception as exc:
                    log.error("fresh pool refill failed: %s", exc)
                    break
            log.debug("fresh pool depth %d/%d",
                      len(self._fresh), self._pool_size)

    # -- assignment ------------------------------------------------------------
    async def container_for(self, sensor_id: str, ip: str) -> dict:
        async with self._lock:
            aff = await self._db.get_affinity(sensor_id, ip)
            if aff is not None:
                if await self.run_sync(self._pod.exists,
                                       aff["container_id"]):
                    await self._ensure_started(aff["container_id"])
                    await self._wait_sshd(aff["ssh_port"])
                    log.info("reusing container %s for %s/%s (port %d)",
                             aff["container_id"][:12], sensor_id, ip,
                             aff["ssh_port"])
                    return self._endpoint(aff, fresh=False)
                log.warning("affinity %s/%s lost container %s; reassigning",
                            sensor_id, ip, aff["container_id"][:12])
                await self._db.delete_affinity(sensor_id, ip)
                self._free_port(aff["ssh_port"])
            if self._fresh:
                fresh = self._fresh.pop(0)
            else:
                fresh = await self._create_fresh()
            cid = fresh["container_id"]
            try:
                await self._ensure_started(cid)
                await self._wait_sshd(fresh["port"])
                container_ip = await self.run_sync(self._pod.container_ip,
                                                   cid)
                await self._db.set_affinity(
                    sensor_id, ip, cid, fresh["port"], fresh["password"],
                    container_ip)
            except Exception as exc:
                log.warning("container assignment for %s/%s failed: %s",
                            sensor_id, ip, exc)
                self._free_port(fresh["port"])
                try:
                    await self.run_sync(self._pod.remove, cid)
                except Exception:
                    pass
                raise
            log.info("assigned fresh container %s to %s/%s (port %d)",
                     cid[:12], sensor_id, ip, fresh["port"])
            asyncio.create_task(self._refill())
            return {
                "container_id": cid,
                "ssh_host": self._ssh_host,
                "ssh_port": fresh["port"],
                "ssh_user": self._user,
                "ssh_password": fresh["password"],
                "fresh": True,
            }

    def _endpoint(self, aff: dict, fresh: bool) -> dict:
        return {
            "container_id": aff["container_id"],
            "ssh_host": self._ssh_host,
            "ssh_port": aff["ssh_port"],
            "ssh_user": self._user,
            "ssh_password": aff["ssh_password"],
            "fresh": fresh,
        }

    async def _ensure_started(self, cid: str):
        status = await self.run_sync(self._pod.status, cid)
        if status != "running":
            log.info("starting container %s (was %s)", cid[:12], status)
            await self.run_sync(self._pod.start, cid)
        else:
            log.debug("container %s already running", cid[:12])

    async def _wait_sshd(self, port: int, timeout: float = 30.0):
        """Wait until the published sshd port accepts TCP (host keys and
        sshd take a few seconds on first boot). Probes the sensor-facing
        address first (the same endpoint sensors will use), falling back to
        loopback: inside a container 127.0.0.1 is the container itself, so a
        bare loopback probe would never succeed there."""
        import time
        hosts = [self._ssh_host]
        if self._ssh_host != "127.0.0.1":
            hosts.append("127.0.0.1")
        deadline = time.monotonic() + timeout
        last_exc: Exception | None = None
        while time.monotonic() < deadline:
            for host in hosts:
                try:
                    _reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), 2.0)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    log.debug("sshd on port %d is up", port)
                    return
                except Exception as exc:
                    last_exc = exc
            await asyncio.sleep(0.5)
        raise PodmanError(f"sshd on port {port} never came up: {last_exc}")

    # -- session tracking / keep-warm -------------------------------------------
    async def session_started(self, sensor_id: str, ip: str):
        key = (sensor_id, ip)
        self._refcounts[key] = self._refcounts.get(key, 0) + 1
        task = self._warm_tasks.pop(key, None)
        if task is not None:
            task.cancel()
            log.debug("keep-warm cancelled for %s/%s (new session)",
                      sensor_id, ip)
        log.debug("session started %s/%s (active=%d)",
                  sensor_id, ip, self._refcounts[key])

    async def session_ended(self, sensor_id: str, ip: str):
        key = (sensor_id, ip)
        left = self._refcounts.get(key, 1) - 1
        self._refcounts[key] = max(0, left)
        await self._db.touch_affinity_end(sensor_id, ip)
        log.debug("session ended %s/%s (active=%d, keep-warm=%ds)",
                  sensor_id, ip, self._refcounts[key], self._keep_warm_s)
        if left <= 0 and key not in self._warm_tasks:
            self._warm_tasks[key] = asyncio.create_task(
                self._warm_stop(sensor_id, ip))

    def is_active(self, sensor_id: str, ip: str) -> bool:
        return self._refcounts.get((sensor_id, ip), 0) > 0

    async def _warm_stop(self, sensor_id: str, ip: str):
        try:
            if self._keep_warm_s > 0:
                await asyncio.sleep(self._keep_warm_s)
            if self.is_active(sensor_id, ip):
                log.debug("keep-warm for %s/%s superseded by new session",
                          sensor_id, ip)
                return
            aff = await self._db.get_affinity(sensor_id, ip)
            if aff is None:
                log.debug("keep-warm for %s/%s: affinity gone",
                          sensor_id, ip)
                return
            log.info("keep-warm expired for %s/%s; stopping %s",
                     sensor_id, ip, aff["container_id"][:12])
            await self.run_sync(self._pod.stop, aff["container_id"])
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            log.warning("warm stop failed: %s", exc)
        finally:
            self._warm_tasks.pop((sensor_id, ip), None)

    # -- removal ------------------------------------------------------------------
    async def remove_affinity(self, sensor_id: str, ip: str):
        task = self._warm_tasks.pop((sensor_id, ip), None)
        if task is not None:
            task.cancel()
        aff = await self._db.get_affinity(sensor_id, ip)
        if aff is None:
            log.debug("remove_affinity %s/%s: no such affinity",
                      sensor_id, ip)
            return
        await self.run_sync(self._pod.remove, aff["container_id"])
        self._free_port(aff["ssh_port"])
        await self._db.delete_affinity(sensor_id, ip)
        self._refcounts.pop((sensor_id, ip), None)
        log.info("removed affinity %s/%s (container %s, port %d)",
                 sensor_id, ip, aff["container_id"][:12], aff["ssh_port"])
