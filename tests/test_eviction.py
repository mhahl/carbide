import datetime
import unittest

from carbide.common.config import validate
from carbide.server.eviction import EvictionJob
from tests.fakes import FakeDatabase, FakePodman


def make_config(**over):
    raw = {
        "role": "server",
        "server": {"tokens": {"s1": "tok"}, "db_dsn": "x",
                   "blob_dir": "y"},
        "podman": {"image": "img"},
        "affinity": {"max_containers": 10,
                     "idle_ttl_active_days": 30,
                     "idle_ttl_inactive_hours": 24},
    }
    for section, values in over.items():
        raw.setdefault(section, {}).update(values)
    return validate(raw)


class FakePool:
    def __init__(self, pod, active=()):
        self._pod = pod
        self.active = set(active)
        self.removed = []

    async def run_sync(self, fn, *a, **k):
        return fn(*a, **k)

    def is_active(self, sensor_id, ip):
        return (sensor_id, ip) in self.active

    async def remove_affinity(self, sensor_id, ip):
        self.removed.append((sensor_id, ip))


class FakeForensics:
    def __init__(self):
        self.calls = []

    async def collect(self, **kwargs):
        self.calls.append(kwargs)
        return {}


NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


class EvictionTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.db = FakeDatabase()
        self.pod = FakePodman()
        self.pool = FakePool(self.pod)
        self.forensics = FakeForensics()
        self.job = EvictionJob(self.pool, self.pod, self.db,
                               self.forensics, make_config())

    async def _aff(self, ip, age_h, active_flag, ended=True):
        cid = self.pod.create_container(f"c-{ip}", "img", "u", 1, "",
                                        {}, 1, 1)
        created = NOW - datetime.timedelta(hours=age_h + 1)
        ended_at = NOW - datetime.timedelta(hours=age_h) if ended else None
        await self.db.set_affinity("s1", ip, cid, 22000 + len(self.db.affinities),
                                   "pw", "", created_at=created,
                                   last_session_end=ended_at,
                                   has_activity=active_flag)
        return cid

    async def test_inactive_ttl_evicts(self):
        cid = await self._aff("1.1.1.1", 25, False)
        await self.db.add_snapshot("s1", "1.1.1.1", cid, "snap-old")
        await self.job.run_once(now=NOW)
        self.assertEqual(self.pool.removed, [("s1", "1.1.1.1")])
        self.assertEqual(len(self.forensics.calls), 1)
        call = self.forensics.calls[0]
        self.assertTrue(call["final"])
        self.assertIn("eviction", call["reason"])
        snaps = await self.db.list_snapshots("s1", "1.1.1.1")
        self.assertEqual(snaps, [])

    async def test_active_ttl_keeps(self):
        await self._aff("2.2.2.2", 25, True)
        await self.job.run_once(now=NOW)
        self.assertEqual(self.pool.removed, [])

    async def test_active_ttl_expires(self):
        await self._aff("3.3.3.3", 31 * 24, True)
        await self.job.run_once(now=NOW)
        self.assertEqual(self.pool.removed, [("s1", "3.3.3.3")])

    async def test_active_session_skipped(self):
        await self._aff("4.4.4.4", 500, False)
        self.pool.active.add(("s1", "4.4.4.4"))
        await self.job.run_once(now=NOW)
        self.assertEqual(self.pool.removed, [])

    async def test_lru_backstop(self):
        job = EvictionJob(self.pool, self.pod, self.db, self.forensics,
                          make_config(affinity={"max_containers": 2,
                                                "idle_ttl_active_days": 30,
                                                "idle_ttl_inactive_hours": 24}))
        await self._aff("a", 1, True)
        await self._aff("b", 2, True)
        await self._aff("c", 3, True)
        await job.run_once(now=NOW)
        self.assertEqual(self.pool.removed, [("s1", "c")])

    async def test_final_archive_failure_still_evicts(self):
        await self._aff("5.5.5.5", 500, False)

        class Boom(FakeForensics):
            async def collect(self, **kwargs):
                raise RuntimeError("boom")

        self.job._forensics = Boom()
        await self.job.run_once(now=NOW)
        self.assertEqual(self.pool.removed, [("s1", "5.5.5.5")])


if __name__ == "__main__":
    unittest.main()
