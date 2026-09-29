"""carbide-server entrypoint."""
import argparse
import asyncio
import getpass
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
    parser.add_argument("--ensure-admin", metavar="USER", default=None,
                        help="create console user USER if missing "
                             "(password from CARBIDE_ADMIN_PASSWORD "
                             "or prompt), then exit")
    parser.add_argument("--set-password", metavar="USER", default=None,
                        help="reset console user USER's password, then exit")
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
    if args.ensure_admin or args.set_password:
        return asyncio.run(_admin_account(
            cfg, args.ensure_admin, args.set_password))
    setup_logging(cfg)
    app = ServerApp(cfg)
    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        pass
    return 0


async def _admin_account(cfg, ensure_user, set_user):
    from .db import Database
    from .web.auth import hash_password
    username = ensure_user or set_user
    password = os.environ.get("CARBIDE_ADMIN_PASSWORD", "")
    if not password:
        try:
            password = getpass.getpass(f"password for {username}: ")
        except (EOFError, KeyboardInterrupt):
            print("carbide-server: no password given", file=sys.stderr)
            return 2
    if len(password) < 8:
        print("carbide-server: password min 8 chars", file=sys.stderr)
        return 2
    db = Database(cfg.section("server")["db_dsn"])
    try:
        await db.connect()
    except Exception as exc:
        print(f"carbide-server: db connect failed: {exc}", file=sys.stderr)
        return 1
    try:
        existing = await db.get_web_user_by_name(username)
        if ensure_user:
            if existing is not None:
                print(f"admin {username} already exists")
                return 0
            await db.create_web_user(username, hash_password(password))
            print(f"admin {username} created")
            return 0
        if existing is None:
            print(f"carbide-server: no such user {username}",
                  file=sys.stderr)
            return 1
        await db.set_web_user_password(existing["id"],
                                       hash_password(password))
        print(f"password updated for {username}")
        return 0
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(main())
