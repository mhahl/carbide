import unittest

from carbide.common.config import validate
from carbide.server.pool import (HONEY_IMAGE_SETTING, REF_NAME, Pool,
                                 same_image_ref)
from carbide.server.podman_wrap import PodmanError, split_pull_ref
from tests.fakes import FakeDatabase, FakePodman


def make_config(**over):
    podman = {"image": "img", "port_range_start": 22000,
              "port_range_end": 22010}
    affinity = {"keep_warm_minutes": 0}
    podman.update(over.pop("podman", {}))
    affinity.update(over.pop("affinity", {}))
    raw = {
        "role": "server",
        "server": {"sensor_token": "tok", "db_dsn": "x",
                   "blob_dir": "y"},
        "podman": podman,
        "affinity": affinity,
    }
    raw.update(over)
    return validate(raw)


class PoolTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.db = FakeDatabase()
        self.pod = FakePodman()
        self.pool = Pool(self.pod, self.db, make_config())
        # FakePod listens on nothing; stub sshd readiness before start
        # (refill now waits for sshd per spare; tested live below
        # against a real socket).
        async def _ready(*args, **kwargs):
            return None
        self.pool._wait_sshd = _ready
        await self.pool.start()

    def test_fresh_pool_prefilled(self):
        self.assertEqual(len(self.pod.containers), 3)  # ref + 2 fresh

    def test_fresh_pool_is_hot(self):
        for fresh in self.pool._fresh:
            self.assertEqual(
                self.pod.status(fresh["container_id"]), "running")

    def test_same_image_ref(self):
        self.assertTrue(same_image_ref("x:1", "x:1"))
        self.assertTrue(same_image_ref("localhost/x:1", "x:1"))
        self.assertTrue(same_image_ref("localhost/x:latest", "x"))
        self.assertFalse(same_image_ref("x:1", "x:2"))
        self.assertFalse(same_image_ref("", "x"))
        self.assertFalse(same_image_ref("x:1", ""))

    def test_split_pull_ref(self):
        self.assertEqual(split_pull_ref("name"), ("name", "latest"))
        self.assertEqual(split_pull_ref("name:tag"), ("name", "tag"))
        self.assertEqual(split_pull_ref("host:5000/name"),
                         ("host:5000/name", "latest"))
        self.assertEqual(split_pull_ref("host:5000/name:tag"),
                         ("host:5000/name", "tag"))

    async def test_current_image_override(self):
        self.assertEqual(await self.pool.current_image(), "img")
        await self.db.set_setting(HONEY_IMAGE_SETTING, "custom:2")
        self.assertEqual(await self.pool.current_image(), "custom:2")
        await self.db.set_setting(HONEY_IMAGE_SETTING, "   ")
        self.assertEqual(await self.pool.current_image(), "img")

    async def test_refresh_reference_recreates_on_image_change(self):
        old = [cid for cid, info in self.pod.containers.items()
               if info["name"] == REF_NAME]
        self.assertEqual(len(old), 1)
        await self.pool.refresh_reference()
        # Same image: baseline untouched.
        self.assertIn(old[0], self.pod.containers)
        await self.db.set_setting(HONEY_IMAGE_SETTING, "img:2")
        await self.pool.refresh_reference()
        self.assertNotIn(old[0], self.pod.containers)
        info = self.pod.inspect(REF_NAME)
        self.assertEqual(info["Config"]["Image"], "img:2")
        refs = [cid for cid, i in self.pod.containers.items()
                if i["name"] == REF_NAME]
        self.assertEqual(len(refs), 1)

    async def test_fresh_spares_use_effective_image(self):
        await self.db.set_setting(HONEY_IMAGE_SETTING, "img:3")
        spare = await self.pool._create_fresh()
        try:
            info = self.pod.inspect(spare["container_id"])
            self.assertEqual(info["Config"]["Image"], "img:3")
        finally:
            await self.pool.run_sync(
                self.pod.remove, spare["container_id"])

    async def test_hot_assign_does_not_restart(self):
        starts = []
        orig_start = self.pod.start

        def counting(cid):
            starts.append(cid)
            return orig_start(cid)

        self.pod.start = counting
        ep = await self.pool.container_for("s1", "1.2.3.4")
        self.assertTrue(ep["fresh"])
        self.assertEqual(starts, [])

    async def test_create_fresh_cleans_up_on_wait_failure(self):
        before_containers = set(self.pod.containers)
        before_ports = set(self.pool._used_ports)

        async def _never(*args, **kwargs):
            raise PodmanError("sshd never came up")

        self.pool._wait_sshd = _never
        with self.assertRaises(PodmanError):
            await self.pool._create_fresh()
        self.assertEqual(set(self.pod.containers), before_containers)
        self.assertEqual(set(self.pool._used_ports), before_ports)

    async def test_new_ip_gets_fresh_running_container(self):
        ep = await self.pool.container_for("s1", "1.2.3.4")
        self.assertTrue(ep["fresh"])
        self.assertEqual(self.pod.status(ep["container_id"]), "running")
        aff = await self.db.get_affinity("s1", "1.2.3.4")
        self.assertEqual(aff["container_id"], ep["container_id"])
        self.assertEqual(aff["ssh_password"], ep["ssh_password"])

    async def test_same_ip_reuses_container(self):
        first = await self.pool.container_for("s1", "1.2.3.4")
        second = await self.pool.container_for("s1", "1.2.3.4")
        self.assertFalse(second["fresh"])
        self.assertEqual(first["container_id"], second["container_id"])

    async def test_other_sensor_gets_own_container(self):
        a = await self.pool.container_for("s1", "1.2.3.4")
        b = await self.pool.container_for("s2", "1.2.3.4")
        self.assertNotEqual(a["container_id"], b["container_id"])

    async def test_restarts_stopped_container(self):
        ep = await self.pool.container_for("s1", "1.2.3.4")
        self.pod.stop(ep["container_id"])
        again = await self.pool.container_for("s1", "1.2.3.4")
        self.assertEqual(again["container_id"], ep["container_id"])
        self.assertEqual(self.pod.status(ep["container_id"]), "running")

    async def test_missing_container_reassigned(self):
        ep = await self.pool.container_for("s1", "1.2.3.4")
        self.pod.remove(ep["container_id"])
        again = await self.pool.container_for("s1", "1.2.3.4")
        self.assertTrue(again["fresh"])
        self.assertNotEqual(again["container_id"], ep["container_id"])

    async def test_keep_warm_zero_stops_on_last_end(self):
        ep = await self.pool.container_for("s1", "1.2.3.4")
        await self.pool.session_started("s1", "1.2.3.4")
        await self.pool.session_started("s1", "1.2.3.4")
        await self.pool.session_ended("s1", "1.2.3.4")
        self.assertTrue(self.pool.is_active("s1", "1.2.3.4"))
        await self.pool.session_ended("s1", "1.2.3.4")
        self.assertFalse(self.pool.is_active("s1", "1.2.3.4"))
        import asyncio
        await asyncio.sleep(0.1)
        self.assertEqual(self.pod.status(ep["container_id"]), "exited")
        # filesystem (affinity) survives the stop
        self.assertIsNotNone(await self.db.get_affinity("s1", "1.2.3.4"))

    async def test_port_exhaustion(self):
        cfg = make_config(podman={"image": "img", "port_range_start": 1,
                                  "port_range_end": 1, "pool_size": 0})
        db, pod = FakeDatabase(), FakePodman()
        pool = Pool(pod, db, cfg)
        await pool.start()

        async def _ready(*args, **kwargs):
            return None
        pool._wait_sshd = _ready
        await pool.container_for("s1", "9.9.9.9")
        with self.assertRaises(PodmanError):
            await pool.container_for("s1", "8.8.8.8")

    async def test_reconcile_drops_missing_and_strays(self):
        await self.db.set_affinity("s1", "1.1.1.1", "gone", 22005,
                                   "pw", "")
        stray = self.pod.create_container("carbide-stray", "img", "u",
                                          22100, "", {}, 1, 1)
        await self.pool._reconcile()
        self.assertIsNone(await self.db.get_affinity("s1", "1.1.1.1"))
        self.assertFalse(self.pod.exists(stray))
        self.assertTrue(self.pod.exists("carbide-ref"))

    async def test_wait_sshd_real_socket(self):
        import asyncio
        server = await asyncio.start_server(
            lambda r, w: None, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            await Pool._wait_sshd(self.pool, port, timeout=5.0)
        finally:
            server.close()
            await server.wait_closed()

    async def test_wait_sshd_timeout(self):
        with self.assertRaises(PodmanError):
            await Pool._wait_sshd(self.pool, 1, timeout=0.1)

    async def test_wait_sshd_probes_ssh_host_first(self):
        # Container case: loopback is dead (the server runs in a container,
        # siblings live on the host), but the sensor-facing address answers.
        import asyncio
        from unittest import mock
        server = await asyncio.start_server(
            lambda r, w: None, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        cfg = make_config(podman={"image": "img", "port_range_start": 22000,
                                  "port_range_end": 22010,
                                  "ssh_host": "sensor-facing.invalid"})
        pool = Pool(FakeDatabase(), FakePodman(), cfg)
        real_open = asyncio.open_connection
        calls = []

        async def fake_open(host, *args, **kwargs):
            calls.append(host)
            if host == "sensor-facing.invalid":
                return await real_open("127.0.0.1", port)
            raise ConnectionRefusedError(host)

        try:
            with mock.patch.object(asyncio, "open_connection", fake_open):
                await pool._wait_sshd(54321, timeout=5.0)
        finally:
            server.close()
            await server.wait_closed()
        self.assertEqual(calls[0], "sensor-facing.invalid")

    async def test_remove_affinity(self):
        ep = await self.pool.container_for("s1", "1.2.3.4")
        await self.pool.remove_affinity("s1", "1.2.3.4")
        self.assertFalse(self.pod.exists(ep["container_id"]))
        self.assertIsNone(await self.db.get_affinity("s1", "1.2.3.4"))
        self.assertNotIn(ep["ssh_port"], self.pool._used_ports)


if __name__ == "__main__":
    unittest.main()
