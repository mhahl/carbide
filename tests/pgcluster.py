"""Throwaway Postgres clusters for integration tests.

Runs initdb/pg_ctl as the unprivileged ``postgres`` user (Postgres refuses to
run as root) in a temp dir, with trust auth on 127.0.0.1.
"""
import os
import shutil
import socket
import subprocess
import tempfile
import time

_PG_BIN = "/usr/sbin"


def postgres_available() -> bool:
    if not all(shutil.which(c, path=f"{_PG_BIN}:/usr/bin:/bin") for c in
               ("initdb", "pg_ctl", "psql")):
        return False
    if not shutil.which("runuser"):
        return False
    try:
        subprocess.run(["id", "postgres"], check=True,
                       capture_output=True)
    except subprocess.CalledProcessError:
        return False
    return True


def _run_as_postgres(*args, **kwargs):
    return subprocess.run(
        ["runuser", "-u", "postgres", "--", *args],
        capture_output=True, text=True, **kwargs)


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class PgCluster:
    def __init__(self):
        self.tmp = None
        self.port = None
        self.dsn = None

    def start(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="carbide-pg-")
        data = os.path.join(self.tmp.name, "data")
        os.makedirs(data)
        os.system(f"chown -R postgres:postgres {self.tmp.name}")
        result = _run_as_postgres(f"{_PG_BIN}/initdb", "-D", data,
                                  "-E", "UTF8", "--no-locale")
        if result.returncode != 0:
            raise RuntimeError(f"initdb failed: {result.stderr[-2000:]}")
        with open(os.path.join(data, "pg_hba.conf"), "a") as fh:
            fh.write("host all all 127.0.0.1/32 trust\n")
        self.port = free_port()
        log = os.path.join(self.tmp.name, "pg.log")
        result = _run_as_postgres(
            f"{_PG_BIN}/pg_ctl", "-D", data, "-l", log,
            "-o", f"-p {self.port} -k {self.tmp.name}",
            "-w", "-t", "60", "start")
        if result.returncode != 0:
            raise RuntimeError(f"pg_ctl start failed: {result.stderr[-2000:]}")
        for _ in range(100):
            result = _run_as_postgres(
                f"{_PG_BIN}/psql", "-h", "127.0.0.1", "-p", str(self.port),
                "-U", "postgres", "-c", "CREATE DATABASE carbide")
            if result.returncode == 0:
                break
            time.sleep(0.2)
        self.dsn = (f"postgresql://postgres@127.0.0.1:{self.port}/carbide")
        return self.dsn

    def stop(self):
        if self.tmp is None:
            return
        try:
            _run_as_postgres(f"{_PG_BIN}/pg_ctl", "-D",
                             os.path.join(self.tmp.name, "data"),
                             "-w", "-t", "30", "stop")
        except Exception:
            pass
        self.tmp.cleanup()
        self.tmp = None
