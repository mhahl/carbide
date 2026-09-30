"""ServerApp wiring: optional workers follow their config flags."""
import os
import tempfile
import unittest

from carbide.common.config import validate
from carbide.server.app import ServerApp
from tests.fakes import FakeDatabase, FakePodman


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


class ServerAppTest(unittest.TestCase):
    def _app(self, cfg):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cfg.section("server")["blob_dir"] = os.path.join(tmp.name, "blobs")
        return ServerApp(cfg, db=FakeDatabase(), podman=FakePodman())

    def test_defaults_vt_present_ipintel_on(self):
        # The vt queue always exists; it idles quietly with no key.
        app = self._app(make_cfg())
        self.assertIsNotNone(app.vt)
        self.assertIsNotNone(app.ipintel)
        self.assertIsNotNone(app.squid)

    def test_workers_opt_out(self):
        app = self._app(make_cfg(
            ipintel={"enabled": False},
            squid={"enabled": False},
            web={"enabled": False}))
        self.assertIsNotNone(app.vt)
        self.assertIsNone(app.ipintel)
        self.assertIsNone(app.squid)
        self.assertIsNone(app.web)


if __name__ == "__main__":
    unittest.main()
