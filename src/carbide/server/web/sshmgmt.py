"""Sensor remote management over SSH (asyncssh client).

Push/restart/provision run the sensor host's own setup.sh, so remote
behavior matches a manual install. Provisioning ships the compose files
from ``[sensor_mgmt] files_dir`` (or a checkout-relative fallback) via
SFTP, writes the remote ``.env``, and runs setup end to end.
"""
import json
import logging
import os
import re
import secrets

import asyncssh

log = logging.getLogger("carbide.server.mgmt")

SENSOR_FILES = ("compose.yml", "config.toml.tmpl", ".env.example",
                "setup.sh")

TAG_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")


class MgmtError(Exception):
    pass


def valid_image_tag(tag) -> str:
    """Console-managed sensor image tag, blank defaulting to 'latest'.

    Raises MgmtError unless the tag is a plain docker tag — also the
    shell-safety gate, since tags interpolate into remote commands.
    """
    tag = (tag or "").strip() or "latest"
    if not TAG_RE.fullmatch(tag):
        raise MgmtError(f"bad image tag {tag!r}")
    return tag


def toml_str_list(passwords: list) -> str:
    """Render ['a','b'] as the AUTH_PASSWORDS TOML fragment."""
    return ", ".join(json.dumps(p) for p in passwords)


def passwords_from_text(text: str) -> list:
    return [line.strip() for line in (text or "").splitlines()
            if line.strip()]


class SensorManager:
    def __init__(self, cfg, server_token: str):
        mgmt = cfg.section("sensor_mgmt")
        self._enabled = mgmt["enabled"]
        self._key_path = mgmt["key_path"]
        self._user = mgmt["user"]
        self._port = mgmt["port"]
        self._timeout = mgmt["connect_timeout_s"]
        self._files_dir = mgmt.get("files_dir", "")
        self._server_token = server_token

    @property
    def enabled(self) -> bool:
        return self._enabled and bool(self._key_path)

    def status(self) -> dict:
        """Console display state (never includes key material)."""
        return {"enabled": self.enabled,
                "key_path": self._key_path or "(unset)",
                "user": self._user, "configured": self._enabled}

    def files_dir(self) -> str:
        if self._files_dir:
            base = self._files_dir
        else:
            here = os.path.dirname(os.path.abspath(__file__))
            base = os.path.normpath(os.path.join(
                here, "..", "..", "..", "..", "compose", "sensor"))
        missing = [name for name in SENSOR_FILES
                   if not os.path.isfile(os.path.join(base, name))]
        if missing:
            raise MgmtError(
                f"sensor files missing in {base}: {', '.join(missing)} "
                "(set [sensor_mgmt] files_dir)")
        return base

    async def _connect(self, sensor: dict):
        if not self.enabled:
            raise MgmtError("sensor management not configured "
                            "([sensor_mgmt] enabled + key_path)")
        try:
            return await asyncssh.connect(
                sensor["ssh_host"], sensor["ssh_port"] or self._port,
                username=sensor["ssh_user"] or self._user,
                client_keys=[self._key_path],
                known_hosts=None, connect_timeout=self._timeout)
        except Exception as exc:
            raise MgmtError(f"ssh to {sensor['ssh_host']} failed: {exc}")

    @staticmethod
    async def _run(conn, command: str, timeout: int = 180) -> dict:
        try:
            result = await conn.run(command, timeout=timeout)
        except Exception as exc:
            return {"ok": False, "exit": -1,
                    "output": f"command failed: {exc}"}
        output = (result.stdout or "") + (result.stderr or "")
        return {"ok": result.exit_status == 0,
                "exit": result.exit_status, "output": output[-6000:]}

    @staticmethod
    def _tag(sensor: dict) -> str:
        return valid_image_tag(sensor.get("image_tag"))

    def render_env(self, sensor: dict) -> str:
        try:
            passwords = json.loads(sensor["auth_passwords"] or "[]")
        except ValueError:
            passwords = []
        lines = [
            f"TAG={self._tag(sensor)}",
            f"SERVER_HOST={sensor['server_host']}",
            f"SERVER_PORT={sensor['server_port']}",
            f"SENSOR_ID={sensor['sensor_id']}",
            f"SENSOR_TOKEN={self._server_token}",
            f"LISTEN_ADDR={sensor['listen_addr']}",
            f"LISTEN_PORT={sensor['listen_port']}",
            # Single-quoted: setup.sh strips one layer for values with
            # spaces; the TOML fragment keeps its double quotes.
            f"AUTH_PASSWORDS='{toml_str_list(passwords)}'",
            f"ACCEPT_PROBABILITY={sensor['accept_probability']}",
        ]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _compose_preamble(remote_dir: str) -> str:
        return (
            f"cd {remote_dir} && "
            "if podman compose version >/dev/null 2>&1; then "
            "COMPOSE='podman compose'; else COMPOSE='podman-compose'; fi"
        )

    async def restart(self, sensor: dict) -> dict:
        """Re-render config and restart the remote stack via its setup.sh
        (idempotent: same command a manual re-run would use)."""
        log.info("mgmt: restarting sensor %s on %s",
                 sensor["sensor_id"], sensor["ssh_host"])
        async with await self._connect(sensor) as conn:
            cmd = (f"cd {sensor['remote_dir']} && "
                   "./setup.sh --skip-pull --skip-firewall")
            return await self._run(conn, cmd, timeout=300)

    async def push_config(self, sensor: dict) -> dict:
        """Append managed overrides to the remote .env (append wins, same
        as setup.sh itself) and re-run setup to pull the image, re-render
        + restart. setup.sh force-recreates, so a pull that changed the
        image updates the container; an unchanged pull is a no-op."""
        # NOTE: firewall intentionally skipped (already fenced at
        # provision); pull intentionally NOT skipped (see docstring).
        try:
            passwords = json.loads(sensor["auth_passwords"] or "[]")
        except ValueError:
            passwords = []
        marker = f"CARBIDE_EOF_{secrets.token_hex(4)}"
        fragment = "\n".join([
            f"TAG={self._tag(sensor)}",
            f"AUTH_PASSWORDS='{toml_str_list(passwords)}'",
            f"ACCEPT_PROBABILITY={sensor['accept_probability']}",
            f"LISTEN_ADDR={sensor['listen_addr']}",
            f"LISTEN_PORT={sensor['listen_port']}",
            f"SERVER_HOST={sensor['server_host']}",
            f"SERVER_PORT={sensor['server_port']}",
        ])
        log.info("mgmt: pushing config to sensor %s on %s",
                 sensor["sensor_id"], sensor["ssh_host"])
        async with await self._connect(sensor) as conn:
            chained = (f"cd {sensor['remote_dir']} && "
                       f"cat >> .env <<'{marker}'\n{fragment}\n{marker}\n"
                       "./setup.sh --skip-firewall")
            return await self._run(conn, chained, timeout=900)

    async def update_image(self, sensor: dict) -> dict:
        """Pull the managed image tag and recreate the remote container.

        No config is pushed: setup.sh --tag persists TAG, pulls, and
        its force-recreate swaps the container when the pull changed
        the image."""
        tag = self._tag(sensor)
        log.info("mgmt: updating sensor %s image to %s",
                 sensor["sensor_id"], tag)
        async with await self._connect(sensor) as conn:
            cmd = (f"cd {sensor['remote_dir']} && "
                   f"./setup.sh --tag {tag} --skip-firewall")
            return await self._run(conn, cmd, timeout=900)

    async def provision(self, sensor: dict) -> dict:
        """Ship compose files, write .env, run full remote setup."""
        base = self.files_dir()
        env = self.render_env(sensor)  # validates the image tag first
        log.info("mgmt: provisioning sensor %s on %s",
                 sensor["sensor_id"], sensor["ssh_host"])
        async with await self._connect(sensor) as conn:
            made = await self._run(
                conn, f"mkdir -p {sensor['remote_dir']}", timeout=60)
            if not made["ok"]:
                return made
            try:
                async with conn.start_sftp_client() as sftp:
                    for name in SENSOR_FILES:
                        await sftp.put(os.path.join(base, name),
                                       f"{sensor['remote_dir']}/{name}")
                    async with sftp.open(
                            f"{sensor['remote_dir']}/.env", "w") as fh:
                        # Text mode: asyncssh encodes str itself.
                        await fh.write(env)
            except Exception as exc:
                return {"ok": False, "exit": -1,
                        "output": f"sftp failed: {exc}"}
            cmd = (f"cd {sensor['remote_dir']} && chmod +x setup.sh && "
                   "./setup.sh")
            return await self._run(conn, cmd, timeout=900)
