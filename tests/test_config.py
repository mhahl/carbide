import textwrap
import unittest

from carbide.common.config import ConfigError, load


def _write(path, body):
    with open(path, "w") as fh:
        fh.write(textwrap.dedent(body))


SENSOR_TOML = """
    role = "sensor"
    [sensor]
    host_key_path = "/etc/carbide/ssh_host_key"
    server_host = "server.vpn"
    sensor_id = "s1"
    token = "tok"
    spool_dir = "/var/spool/carbide"
    [auth]
    passwords = ["honey", "letmein"]
    accept_probability = 0.05
"""

SERVER_TOML = """
    role = "server"
    [server]
    sensor_token = "tok"
    db_dsn = "postgresql://carbide@db/carbide"
    blob_dir = "/var/lib/carbide/blobs"
    [podman]
    image = "carbide-honeypot:latest"
"""


class ConfigTest(unittest.TestCase):
    def test_sensor_valid(self):
        with open("/tmp/cfg-sensor.toml", "w") as fh:
            fh.write(SENSOR_TOML)
        cfg = load("/tmp/cfg-sensor.toml")
        self.assertEqual(cfg.role, "sensor")
        self.assertEqual(cfg.get("sensor.listen_port"), 2222)
        self.assertEqual(cfg.get("auth.passwords"), ["honey", "letmein"])
        self.assertEqual(cfg.get("auth.accept_probability"), 0.05)
        self.assertEqual(cfg.get("logging.level"), "INFO")

    def test_server_valid(self):
        with open("/tmp/cfg-server.toml", "w") as fh:
            fh.write(SERVER_TOML)
        cfg = load("/tmp/cfg-server.toml")
        self.assertEqual(cfg.role, "server")
        self.assertEqual(cfg.get("affinity.max_containers"), 200)
        self.assertTrue(cfg.get("affinity.commit_per_session"))
        self.assertEqual(cfg.get("squid.log_path"), "/var/log/squid/access.log")

    def test_missing_file(self):
        with self.assertRaises(ConfigError):
            load("/tmp/cfg-does-not-exist.toml")

    def test_bad_role(self):
        with open("/tmp/cfg-bad.toml", "w") as fh:
            fh.write('role = "banana"\n')
        with self.assertRaises(ConfigError):
            load("/tmp/cfg-bad.toml")

    def test_wrong_role_section(self):
        with open("/tmp/cfg-bad.toml", "w") as fh:
            fh.write(SENSOR_TOML + "[podman]\nimage = \"x\"\n")
        with self.assertRaises(ConfigError):
            load("/tmp/cfg-bad.toml")

    def test_missing_required(self):
        with open("/tmp/cfg-bad.toml", "w") as fh:
            fh.write('role = "sensor"\n[sensor]\nserver_host = "x"\n')
        with self.assertRaises(ConfigError):
            load("/tmp/cfg-bad.toml")

    def test_bad_probability(self):
        with open("/tmp/cfg-bad.toml", "w") as fh:
            fh.write(SENSOR_TOML + "[auth]\naccept_probability = 1.5\n")
        with self.assertRaises(ConfigError):
            load("/tmp/cfg-bad.toml")

    def test_unknown_key_rejected(self):
        with open("/tmp/cfg-bad.toml", "w") as fh:
            fh.write(SENSOR_TOML + "[auth]\npasswrods = []\n")
        with self.assertRaises(ConfigError):
            load("/tmp/cfg-bad.toml")

    def test_bad_port_range(self):
        with open("/tmp/cfg-bad.toml", "w") as fh:
            fh.write(SERVER_TOML + "[podman]\nport_range_start = 5\n"
                     "port_range_end = 4\n")
        with self.assertRaises(ConfigError):
            load("/tmp/cfg-bad.toml")

    def test_empty_sensor_token_rejected(self):
        with open("/tmp/cfg-bad.toml", "w") as fh:
            fh.write('role = "server"\n[server]\nsensor_token = ""\n'
                     'db_dsn = "x"\nblob_dir = "y"\n[podman]\nimage = "z"\n')
        with self.assertRaises(ConfigError):
            load("/tmp/cfg-bad.toml")


if __name__ == "__main__":
    unittest.main()
