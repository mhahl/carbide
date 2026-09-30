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
import shlex
import shutil
import subprocess
import tempfile
import unittest

try:
    import yaml
except ImportError:  # not a project dependency; compose files are static
    yaml = None

requires_yaml = unittest.skipUnless(yaml is not None, "pyyaml not installed")
requires_bash = unittest.skipUnless(shutil.which("bash") is not None,
                                    "bash not installed")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_COMPOSE = os.path.join(ROOT, "compose", "server", "compose.yml")
SENSOR_COMPOSE = os.path.join(ROOT, "compose", "sensor", "compose.yml")
SERVER_SETUP = os.path.join(ROOT, "compose", "server", "setup.sh")
SENSOR_SETUP = os.path.join(ROOT, "compose", "sensor", "setup.sh")

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
    def test_server_has_net_raw_for_nmap(self):
        # nmap -sV needs raw sockets; podman's default caps lack NET_RAW.
        caps = _load_services(SERVER_COMPOSE)["server"].get("cap_add", [])
        self.assertIn("NET_RAW", caps)

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


def _run_set_env(setup_path, seed, *calls):
    """Run the real set_env() from setup_path against a seeded .env.

    Each call is a (key, value) pair. Returns (text, mode) of .env.
    """
    tmp = tempfile.mkdtemp()
    try:
        env_path = os.path.join(tmp, ".env")
        with open(env_path, "w") as fh:
            fh.write(seed)
        os.chmod(env_path, 0o600)
        driver = ["cd " + shlex.quote(tmp),
                  "sed -n '/^set_env() {/,/^}/p' "
                  + shlex.quote(setup_path) + " > setenv.func",
                  ". ./setenv.func"]
        for key, value in calls:
            driver.append("set_env %s %s"
                          % (shlex.quote(key), shlex.quote(value)))
        subprocess.run(["bash", "-c", "\n".join(driver)], check=True,
                       capture_output=True, text=True)
        with open(env_path) as fh:
            return fh.read(), os.stat(env_path).st_mode & 0o777
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class SetupEnvIdempotenceTest(unittest.TestCase):
    """setup.sh flag handling must not pile duplicate lines into .env.

    Regression: every flag used ``echo "KEY=..." >> .env``, so each
    re-run with the same flags appended another copy. set_env() keeps
    exactly one line per key (and heals old duplicates on next run).
    """

    CASES = (
        ("server", SERVER_SETUP, "API_BIND"),
        ("sensor", SENSOR_SETUP, "SENSOR_ID"),
    )

    @requires_bash
    def test_rerun_never_duplicates(self):
        for name, setup, key in self.CASES:
            with self.subTest(stack=name):
                seed = "# seeded comment\n%s=old\nOTHER=keep\n" % key
                first, mode = _run_set_env(setup, seed, (key, "new"))
                self.assertEqual(first.count("%s=" % key), 1)
                self.assertIn("%s=new\n" % key, first)
                self.assertIn("# seeded comment\n", first)
                self.assertIn("OTHER=keep\n", first)
                self.assertEqual(mode, 0o600)
                # A second identical run changes nothing at all.
                again, _ = _run_set_env(setup, first, (key, "new"))
                self.assertEqual(again, first)

    @requires_bash
    def test_heals_preexisting_duplicates(self):
        for name, setup, key in self.CASES:
            with self.subTest(stack=name):
                seed = "%s=one\n%s=two\n" % (key, key)
                body, _ = _run_set_env(setup, seed, (key, "three"))
                self.assertEqual(body, "%s=three\n" % key)
