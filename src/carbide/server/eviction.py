"""Eviction (D6): tiered idle TTL plus an LRU max-containers backstop. A final
forensic archive (always with a full export attempt) precedes any removal.
"""
import asyncio
import datetime
import logging

log = logging.getLogger("carbide.server.eviction")


def _as_utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value


class EvictionJob:
    def __init__(self, pool, podman, db, forensics, cfg,
                 interval_s: float = 300.0):
        self._pool = pool
        self._pod = podman
        self._db = db
        self._forensics = forensics
        self._max = cfg.get("affinity.max_containers", 200)
        self._ttl_active = datetime.timedelta(
            days=cfg.get("affinity.idle_ttl_active_days", 30))
        self._ttl_inactive = datetime.timedelta(
            hours=cfg.get("affinity.idle_ttl_inactive_hours", 24))
        self._interval = interval_s

    async def run_forever(self):
        log.info("eviction job started (pass every %ss)", self._interval)
        while True:
            await asyncio.sleep(self._interval)
            try:
                await self.run_once()
            except Exception as exc:
                log.warning("eviction pass failed: %s", exc)

    async def run_once(self, now=None):
        now = now or datetime.datetime.now(datetime.timezone.utc)
        scanned, evicted = 0, 0
        for aff in await self._db.list_affinities():
            scanned += 1
            if self._pool.is_active(aff["sensor_id"], aff["attacker_ip"]):
                log.debug("eviction: skipping active %s/%s",
                          aff["sensor_id"], aff["attacker_ip"])
                continue
            last = _as_utc(aff["last_session_end"]) or _as_utc(
                aff["created_at"]) or now
            ttl = self._ttl_active if aff["has_activity"] else self._ttl_inactive
            if now - last > ttl:
                tier = "active" if aff["has_activity"] else "inactive"
                await self._evict(aff, f"idle TTL expired ({tier})")
                evicted += 1
        remaining = [a for a in await self._db.list_affinities()
                     if not self._pool.is_active(a["sensor_id"],
                                                 a["attacker_ip"])]
        if len(remaining) > self._max:
            remaining.sort(key=lambda a: _as_utc(a["last_session_end"]) or
                           _as_utc(a["created_at"]) or now)
            for aff in remaining[:len(remaining) - self._max]:
                await self._evict(aff, "max-containers LRU backstop")
                evicted += 1
        log.info("eviction pass: %d scanned, %d evicted", scanned, evicted)

    async def _evict(self, aff, reason):
        sensor_id, ip = aff["sensor_id"], aff["attacker_ip"]
        log.info("evicting %s/%s: %s", sensor_id, ip, reason)
        latest = await self._db.latest_session(sensor_id, ip)
        if latest:
            session_id = latest[0]
        else:
            session_id = f"final-{sensor_id}-{ip}"
            await self._db.ensure_session(session_id, sensor_id, ip)
        try:
            await self._forensics.collect(
                sensor_id=sensor_id, attacker_ip=ip, session_id=session_id,
                container_id=aff["container_id"],
                reason=f"eviction: {reason}", final=True)
        except Exception as exc:
            log.warning("final archive for %s/%s failed: %s",
                        sensor_id, ip, exc)
        snaps = await self._db.list_snapshots(sensor_id, ip)
        for image, _created in snaps:
            try:
                await self._pool.run_sync(self._pod.remove_image, image)
            except Exception as exc:
                log.warning("snapshot cleanup %s failed: %s", image, exc)
            await self._db.delete_snapshot(image)
        log.debug("evicted %s/%s: removed %d snapshots", sensor_id, ip,
                  len(snaps))
        await self._pool.remove_affinity(sensor_id, ip)
