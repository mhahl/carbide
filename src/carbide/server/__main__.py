"""carbide-server entrypoint."""
import argparse
import asyncio
import logging
import logging.handlers
import os
import sys

from ..common.config import DEFAULT_PATH, ConfigError, load
from .app import ServerApp


def setup_logging(cfg):
    level = getattr(logging, cfg.get("logging.level", "INFO").upper(),
                    logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    logdir = cfg.get("logging.dir", "")
    if logdir:
        os.makedirs(logdir, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            os.path.join(logdir, "carbide-server.log"),
            maxBytes=10 * 1024 * 1024, backupCount=5)
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(name)s %(levelname)s %(message)s"))
    root.addHandler(handler)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="carbide-server")
    parser.add_argument("-c", "--config", default=DEFAULT_PATH)
    args = parser.parse_args(argv)
    try:
        cfg = load(args.config)
    except ConfigError as exc:
        print(f"carbide-server: {exc}", file=sys.stderr)
        return 2
    if cfg.role != "server":
        print("carbide-server: config role must be 'server'",
              file=sys.stderr)
        return 2
    setup_logging(cfg)
    app = ServerApp(cfg)
    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
