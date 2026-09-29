"""carbide-sensor entrypoint."""
import argparse
import asyncio
import logging
import logging.handlers
import os
import sys

import asyncssh

from ..common.config import DEFAULT_PATH, ConfigError, load
from ..common.util import BindError
from .app import SensorApp


def ensure_host_key(path: str):
    if os.path.exists(path):
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(path)
    os.chmod(path, 0o600)


def setup_logging(cfg):
    level = getattr(logging, cfg.get("logging.level", "INFO").upper(),
                    logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    handler = None
    logdir = cfg.get("logging.dir", "")
    if logdir:
        os.makedirs(logdir, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            os.path.join(logdir, "carbide-sensor.log"),
            maxBytes=10 * 1024 * 1024, backupCount=5)
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(name)s %(levelname)s %(message)s"))
    root.addHandler(handler)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="carbide-sensor")
    parser.add_argument("-c", "--config", default=DEFAULT_PATH)
    args = parser.parse_args(argv)
    try:
        cfg = load(args.config)
    except ConfigError as exc:
        print(f"carbide-sensor: {exc}", file=sys.stderr)
        return 2
    if cfg.role != "sensor":
        print("carbide-sensor: config role must be 'sensor'",
              file=sys.stderr)
        return 2
    setup_logging(cfg)
    ensure_host_key(cfg.get("sensor.host_key_path"))
    app = SensorApp(cfg)
    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        pass
    except BindError as exc:
        print(f"carbide-sensor: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
