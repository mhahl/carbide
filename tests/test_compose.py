"""Compose-file guardrails: file bind mounts must not auto-create host paths.

Regression test for::

    crun: mount `/run/podman/podman.sock` to `run/podman/podman.sock`:
    Not a directory

Cause: podman-compose silently ``makedirs()`` a missing short-syntax bind
source. When ``/run/podman/podman.sock`` was missing (``podman.socket``
down, e.g. after a reboot), ``up`` created it as a *directory*; a
container created against one host-path type and (re)started against the
other fails in crun with ENOTDIR. The stale mountpoint type is baked into
the container rootfs, so only recreation recovers.

Fix: bind mounts whose target is a host *file* (the socket, the rendered
config) use long syntax with ``bind.create_host_path: false``, turning a
missing source into a loud compose error instead of a wedged container.
Confined services (no ``label=disable``) must also keep an SELinux
relabel on host binds, or reads fail with permission denied.
"""
import os
import unittest

try:
    import yaml
except ImportError:  # not a project dependency; compose files are static
    yaml = None

requires_yaml = unittest.skipUnless(yaml is not None, "pyyaml not installed")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_COMPOSE = os.path.join(ROOT, "compose", "server", "compose.yml")
SENSOR_COMPOSE = os.path.join(ROOT, "compose", "sensor", "compose.yml")

# Container paths backed by host FILES. A directory auto-created at any of
# these wedges (re)starts with crun ENOTDIR once the real file appears.
FILE_TARGETS = ("/run/podman/podman.sock", "/etc/carbide/config.toml")


def _binds(entries):
    """Yield (source, target, bind_opts) for bind mounts only.

    Short-syntax binds auto-create a missing host source (the bug), so
    they report create_host_path True. Entries with ${...} interpolation
    are skipped: their shape is deploy-time (BLOB_MOUNT defaults to a
    named volume; an NFS override is intentionally directory semantics).
    """
    for entry in entries or []:
        if isinstance(entry, dict):
            if entry.get("type") == "bind":
                yield (entry.get("source"), entry.get("target"),
                       entry.get("bind") or {})
            continue
        if "$" in entry:
            continue
        parts = entry.split(":")
        if len(parts) < 2:
            continue  # anonymous volume
        source, target = parts[0], parts[1]
        if not source.startswith(("/", ".", "~")):
            continue  # named volume
        yield (source, target, {"create_host_path": True})


def _load_services(path):
    with open(path) as fh:
        return yaml.safe_load(fh)["services"]


class ComposeBindTest(unittest.TestCase):
    @requires_yaml
    def test_server_socket_bind_no_autocreate(self):
        binds = list(_binds(
            _load_services(SERVER_COMPOSE)["server"].get("volumes")))
        matches = [b for b in binds
                   if b[1] == "/run/podman/podman.sock"]
        self.assertEqual(len(matches), 1, "server must bind the host socket")
        self.assertIs(matches[0][2].get("create_host_path"), False)

    @requires_yaml
    def test_server_unconfined(self):
        # The server's binds carry no SELinux relabel (long syntax has no
        # :z); that is only safe because the service runs unconfined.
        opts = _load_services(SERVER_COMPOSE)["server"].get(
            "security_opt", [])
        self.assertIn("label=disable", opts)

    @requires_yaml
    def test_config_binds_no_autocreate(self):
        for path, svc in ((SERVER_COMPOSE, "server"),
                          (SENSOR_COMPOSE, "sensor")):
            with self.subTest(compose=path):
                binds = list(_binds(
                    _load_services(path)[svc].get("volumes")))
                matches = [b for b in binds
                           if b[1] == "/etc/carbide/config.toml"]
                self.assertEqual(len(matches), 1,
                                 f"{svc} must bind the rendered config")
                self.assertIs(matches[0][2].get("create_host_path"), False)

    @requires_yaml
    def test_sensor_config_bind_keeps_relabel(self):
        # The sensor is confined (no label=disable): without a relabel it
        # cannot read the host config file (permission denied).
        binds = list(_binds(
            _load_services(SENSOR_COMPOSE)["sensor"].get("volumes")))
        matches = [b for b in binds
                   if b[1] == "/etc/carbide/config.toml"]
        self.assertEqual(len(matches), 1)
        self.assertIn(matches[0][2].get("selinux"), ("z", "Z"))

    @requires_yaml
    def test_no_short_syntax_file_binds(self):
        # Generic sweep: any file-target bind in any service of either
        # stack must refuse to auto-create its host source.
        for path in (SERVER_COMPOSE, SENSOR_COMPOSE):
            for svc, spec in _load_services(path).items():
                for _src, target, opts in _binds(spec.get("volumes")):
                    with self.subTest(compose=path, service=svc,
                                      target=target):
                        if target in FILE_TARGETS:
                            self.assertIs(
                                opts.get("create_host_path"), False)
