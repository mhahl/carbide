"""Single-file TOML configuration with strict per-role validation.

Each host runs one role (``sensor`` or ``server``) and keeps the single-file
rule: exactly one config.toml per host, with role-appropriate keys.
"""
import tomllib
from typing import Any

DEFAULT_PATH = "/etc/carbide/config.toml"


class ConfigError(Exception):
    pass


# section -> key -> (type, required, default)
# A validator may be appended as a 4th tuple item: callable(value) -> error|None.
_SCHEMA = {
    "sensor": {
        "listen_addr": (str, False, "0.0.0.0"),
        "listen_port": (int, False, 2222),
        "host_key_path": (str, True, None),
        "server_host": (str, True, None),
        "server_port": (int, False, 8440),
        "sensor_id": (str, True, None),
        "token": (str, True, None),
        "spool_dir": (str, True, None),
        "request_timeout_s": ((int, float), False, 10.0),
        "session_idle_timeout_s": ((int, float), False, 600.0),
        "session_max_time_s": ((int, float), False, 3600.0),
    },
    "auth": {
        "passwords": (list, False, []),
        "accept_probability": ((int, float), False, 0.0),
        "max_attempts": (int, False, 10),
    },
    "server": {
        "api_addr": (str, False, "127.0.0.1"),
        "api_port": (int, False, 8440),
        "sensor_token": (str, True, None),
        "db_dsn": (str, True, None),
        "blob_dir": (str, True, None),
    },
    "podman": {
        "socket": (str, False, "unix:///run/podman/podman.sock"),
        "image": (str, True, None),
        "port_range_start": (int, False, 22000),
        "port_range_end": (int, False, 22100),
        "network": (str, False, ""),
        "container_user": (str, False, "honey"),
        "memory_mb": (int, False, 256),
        "pids_limit": (int, False, 128),
        "pool_size": (int, False, 2),
        "ssh_host": (str, False, ""),
    },
    "affinity": {
        "keep_warm_minutes": (int, False, 10),
        "max_containers": (int, False, 200),
        "idle_ttl_active_days": (int, False, 30),
        "idle_ttl_inactive_hours": (int, False, 24),
        "snapshot_retention": (int, False, 10),
        "commit_per_session": (bool, False, True),
    },
    "forensics": {
        "max_file_bytes": (int, False, 1024 * 1024),
        "include_full_export": (bool, False, False),
    },
    "squid": {
        "enabled": (bool, False, True),
        "mode": (str, False, "transparent"),
        "explicit_proxy": (str, False, ""),
        "log_path": (str, False, "/var/log/squid/access.log"),
    },
    "quotas": {
        "blob_max_bytes": (int, False, 10 * 1024 * 1024 * 1024),
        "session_max_bytes": (int, False, 100 * 1024 * 1024),
    },
    "logging": {
        "level": (str, False, "INFO"),
        "dir": (str, False, ""),
    },
    "web": {
        "enabled": (bool, False, True),
        "bind_addr": (str, False, "127.0.0.1"),
        "port": (int, False, 8080),
        "session_ttl_hours": (int, False, 12),
    },
    "sensor_mgmt": {
        "enabled": (bool, False, False),
        "key_path": (str, False, ""),
        "user": (str, False, "carbide"),
        "port": (int, False, 22),
        "connect_timeout_s": ((int, float), False, 10.0),
        "files_dir": (str, False, ""),
    },
    "virustotal": {
        "enabled": (bool, False, False),
        "api_key": (str, False, ""),
        "requests_per_minute": (int, False, 4),
        "daily_cap": (int, False, 500),
        "max_upload_bytes": (int, False, 32 * 1024 * 1024),
        "rescan_after_days": (int, False, 30),
    },
    "ipintel": {
        "enabled": (bool, False, True),
        "nmap_args": (list, False, ["-sT", "-sV", "--top-ports", "1000"]),
        "cache_days": (int, False, 7),
        "timeout_s": ((int, float), False, 300.0),
        "geo_enabled": (bool, False, True),
    },
}

_ROLE_SECTIONS = {
    "sensor": {"sensor", "auth", "logging"},
    "server": {
        "server", "podman", "affinity", "forensics", "squid", "quotas",
        "logging", "web", "sensor_mgmt", "virustotal", "ipintel",
    },
}


def _check_ranges(section: str, key: str, value: Any) -> None:
    if key in ("listen_port", "server_port", "api_port"):
        if not 1 <= value <= 65535:
            raise ConfigError(f"[{section}] {key} must be 1..65535, got {value!r}")
    if key == "port" and section in ("web", "sensor_mgmt"):
        if not 1 <= value <= 65535:
            raise ConfigError(f"[{section}] {key} must be 1..65535, got {value!r}")
    if key == "accept_probability" and not 0.0 <= value <= 1.0:
        raise ConfigError(
            f"[auth] accept_probability must be 0..1, got {value!r}")
    if key == "max_attempts" and value < 1:
        raise ConfigError(f"[auth] max_attempts must be >= 1, got {value!r}")
    if key == "session_ttl_hours" and value < 1:
        raise ConfigError(f"[web] session_ttl_hours must be >= 1, got {value!r}")
    if key == "connect_timeout_s" and value <= 0:
        raise ConfigError(
            f"[sensor_mgmt] connect_timeout_s must be > 0, got {value!r}")
    if key in ("request_timeout_s", "session_idle_timeout_s", "session_max_time_s"):
        if value <= 0:
            raise ConfigError(f"[sensor] {key} must be > 0, got {value!r}")
    if key in ("keep_warm_minutes", "max_containers", "idle_ttl_active_days",
               "idle_ttl_inactive_hours", "snapshot_retention", "memory_mb",
               "pids_limit", "max_file_bytes", "blob_max_bytes",
               "session_max_bytes", "port_range_start", "port_range_end",
               "pool_size"):
        if value < 0:
            raise ConfigError(f"[{section}] {key} must be >= 0, got {value!r}")
    if key in ("requests_per_minute", "daily_cap", "max_upload_bytes",
               "rescan_after_days", "cache_days"):
        if value < 1:
            raise ConfigError(f"[{section}] {key} must be >= 1, got {value!r}")
    if key == "timeout_s" and value <= 0:
        raise ConfigError(f"[{section}] {key} must be > 0, got {value!r}")


class Config:
    """Validated configuration: ``cfg.get("sensor.listen_port")``."""

    def __init__(self, data: dict):
        self._data = data

    @property
    def role(self) -> str:
        return self._data["role"]

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def section(self, name: str) -> dict:
        value = self._data.get(name, {})
        if not isinstance(value, dict):
            raise ConfigError(f"[{name}] must be a table")
        return value

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"Config(role={self.role!r})"


def load(path: str = DEFAULT_PATH) -> Config:
    try:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}")
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}")
    return validate(raw)


def validate(raw: dict) -> Config:
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a table")
    role = raw.get("role")
    if role not in _ROLE_SECTIONS:
        raise ConfigError(
            f'role must be one of {sorted(_ROLE_SECTIONS)}, got {role!r}')
    allowed = _ROLE_SECTIONS[role]
    data: dict = {"role": role}
    for section, body in raw.items():
        if section == "role":
            continue
        if section not in _SCHEMA:
            raise ConfigError(f"unknown section [{section}]")
        if section not in allowed:
            raise ConfigError(
                f"[{section}] is not valid for role {role!r}")
        if not isinstance(body, dict):
            raise ConfigError(f"[{section}] must be a table")
        schema = _SCHEMA[section]
        for key in body:
            if key not in schema:
                raise ConfigError(f"unknown key [{section}] {key!r}")
        out: dict = {}
        for key, (types, required, default) in schema.items():
            if key in body:
                value = body[key]
            elif required:
                raise ConfigError(f"missing required key [{section}] {key!r}")
            else:
                value = default() if callable(default) else default
                # copy mutable defaults
                if isinstance(value, (list, dict)):
                    value = type(value)(value)
                out[key] = value
                continue
            if not isinstance(value, types) or isinstance(value, bool) and types is int:
                names = getattr(types, "__name__", repr(types))
                raise ConfigError(
                    f"[{section}] {key} must be {names}, got {value!r}")
            _check_ranges(section, key, value)
            out[key] = value
        data[section] = out
    # fill wholly-missing optional sections with defaults
    for section in allowed:
        if section in data:
            continue
        schema = _SCHEMA[section]
        missing = [k for k, (_, req, _) in schema.items() if req]
        if missing:
            raise ConfigError(
                f"missing required section [{section}] (role {role!r})")
        out = {}
        for key, (_, _, default) in schema.items():
            value = default() if callable(default) else default
            if isinstance(value, (list, dict)):
                value = type(value)(value)
            out[key] = value
        data[section] = out
    # cross-field checks
    if role == "server":
        start = data["podman"]["port_range_start"]
        end = data["podman"]["port_range_end"]
        if end < start:
            raise ConfigError(
                "[podman] port_range_end must be >= port_range_start")
        if not data["server"]["sensor_token"]:
            raise ConfigError("[server] sensor_token must not be empty")
        if data["squid"]["mode"] not in ("transparent", "explicit"):
            raise ConfigError(
                '[squid] mode must be "transparent" or "explicit"')
        if data["squid"]["mode"] == "explicit" and not data["squid"]["explicit_proxy"]:
            raise ConfigError(
                "[squid] explicit_proxy is required when mode = explicit")
        if data["virustotal"]["enabled"] and not data["virustotal"]["api_key"]:
            raise ConfigError(
                "[virustotal] api_key is required when enabled = true")
        for arg in data["ipintel"]["nmap_args"]:
            if not isinstance(arg, str) or not arg or arg[:1].isspace():
                raise ConfigError(
                    "[ipintel] nmap_args must be non-empty strings, "
                    f"got {arg!r}")
    return Config(data)
