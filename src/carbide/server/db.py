"""Postgres access for carbide-server: schema, migrations, and queries.

One async connection plus a lock is enough at honeypot scale and avoids an
extra pool dependency. Every sensor record is applied idempotently through
``applied_records``.
"""
import asyncio
import datetime
import logging

import psycopg

log = logging.getLogger("carbide.server.db")


class DatabaseClosedError(Exception):
    """Raised when a query is attempted after :meth:`Database.close`."""

MIGRATIONS = [
    (1, """
    CREATE TABLE IF NOT EXISTS schema_version (version INT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS sensors (
        sensor_id TEXT PRIMARY KEY,
        first_seen TIMESTAMPTZ DEFAULT now(),
        last_seen TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS affinities (
        sensor_id TEXT NOT NULL,
        attacker_ip TEXT NOT NULL,
        container_id TEXT NOT NULL,
        ssh_port INT NOT NULL,
        ssh_password TEXT NOT NULL,
        container_ip TEXT DEFAULT '',
        has_activity BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT now(),
        last_session_end TIMESTAMPTZ,
        PRIMARY KEY (sensor_id, attacker_ip));
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        sensor_id TEXT NOT NULL,
        attacker_ip TEXT NOT NULL,
        username TEXT DEFAULT '',
        container_id TEXT DEFAULT '',
        fresh BOOLEAN,
        over_quota BOOLEAN DEFAULT FALSE,
        started_at TIMESTAMPTZ,
        ended_at TIMESTAMPTZ,
        end_reason TEXT DEFAULT '');
    CREATE INDEX IF NOT EXISTS sessions_affinity_idx
        ON sessions (sensor_id, attacker_ip, started_at);
    CREATE TABLE IF NOT EXISTS auth_attempts (
        id BIGSERIAL PRIMARY KEY,
        session_id TEXT NOT NULL,
        sensor_id TEXT NOT NULL,
        username TEXT DEFAULT '',
        password TEXT DEFAULT '',
        accepted BOOLEAN NOT NULL,
        matched_list BOOLEAN NOT NULL,
        at TIMESTAMPTZ NOT NULL);
    CREATE TABLE IF NOT EXISTS transcripts (
        id BIGSERIAL PRIMARY KEY,
        session_id TEXT NOT NULL,
        channel TEXT DEFAULT '',
        direction TEXT DEFAULT '',
        stream TEXT DEFAULT '',
        seq INT NOT NULL,
        data BYTEA NOT NULL,
        at TIMESTAMPTZ NOT NULL);
    CREATE INDEX IF NOT EXISTS transcripts_session_idx
        ON transcripts (session_id, id);
    CREATE TABLE IF NOT EXISTS blobs (
        sha256 TEXT PRIMARY KEY,
        path TEXT NOT NULL,
        size BIGINT NOT NULL,
        first_seen TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS session_files (
        id BIGSERIAL PRIMARY KEY,
        session_id TEXT NOT NULL,
        name TEXT NOT NULL,
        blob_sha TEXT,
        size BIGINT NOT NULL,
        at TIMESTAMPTZ NOT NULL);
    CREATE TABLE IF NOT EXISTS diffs (
        id BIGSERIAL PRIMARY KEY,
        session_id TEXT NOT NULL,
        path TEXT NOT NULL,
        kind TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS reports (
        session_id TEXT PRIMARY KEY,
        markdown TEXT NOT NULL,
        json TEXT NOT NULL,
        at TIMESTAMPTZ NOT NULL);
    CREATE TABLE IF NOT EXISTS snapshots (
        id BIGSERIAL PRIMARY KEY,
        sensor_id TEXT NOT NULL,
        attacker_ip TEXT NOT NULL,
        container_id TEXT NOT NULL,
        image TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS squid_hits (
        id BIGSERIAL PRIMARY KEY,
        session_id TEXT DEFAULT '',
        sensor_id TEXT DEFAULT '',
        container_ip TEXT DEFAULT '',
        at TIMESTAMPTZ NOT NULL,
        method TEXT DEFAULT '',
        url TEXT DEFAULT '',
        status INT NOT NULL,
        bytes BIGINT NOT NULL,
        mime TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS applied_records (
        record_id TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ DEFAULT now());
    """),
    (2, """
    CREATE TABLE IF NOT EXISTS web_users (
        id BIGSERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        pw_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT now(),
        disabled BOOLEAN DEFAULT FALSE);
    CREATE TABLE IF NOT EXISTS web_sessions (
        token_sha TEXT PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ DEFAULT now(),
        expires_at TIMESTAMPTZ NOT NULL);
    CREATE INDEX IF NOT EXISTS web_sessions_user_idx
        ON web_sessions (user_id);
    CREATE TABLE IF NOT EXISTS managed_sensors (
        sensor_id TEXT PRIMARY KEY,
        ssh_host TEXT NOT NULL,
        ssh_port INT DEFAULT 22,
        ssh_user TEXT DEFAULT '',
        remote_dir TEXT DEFAULT '',
        listen_addr TEXT DEFAULT '0.0.0.0',
        listen_port INT DEFAULT 2222,
        server_host TEXT DEFAULT '',
        server_port INT DEFAULT 8440,
        auth_passwords TEXT DEFAULT '[]',
        accept_probability DOUBLE PRECISION DEFAULT 0.05,
        notes TEXT DEFAULT '',
        updated_at TIMESTAMPTZ DEFAULT now());
    """),
    (3, """
    CREATE TABLE IF NOT EXISTS vt_scans (
        sha256 TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        malicious INT DEFAULT 0,
        suspicious INT DEFAULT 0,
        harmless INT DEFAULT 0,
        undetected INT DEFAULT 0,
        permalink TEXT DEFAULT '',
        report_json TEXT DEFAULT '',
        analysis_id TEXT DEFAULT '',
        error TEXT DEFAULT '',
        scanned_at TIMESTAMPTZ DEFAULT now(),
        updated_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS vt_quota (
        day DATE PRIMARY KEY,
        used INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS ip_intel (
        attacker_ip TEXT PRIMARY KEY,
        rdns TEXT DEFAULT '',
        status TEXT NOT NULL,
        open_ports TEXT DEFAULT '[]',
        raw_xml TEXT DEFAULT '',
        error TEXT DEFAULT '',
        scanned_at TIMESTAMPTZ DEFAULT now());
    """),
    (4, """
    CREATE TABLE IF NOT EXISTS server_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TIMESTAMPTZ DEFAULT now());
    """),
    (5, """
    ALTER TABLE session_files ADD COLUMN IF NOT EXISTS origin TEXT
        NOT NULL DEFAULT 'sensor';
    UPDATE session_files SET origin = 'forensics'
        WHERE name LIKE 'container:%';
    """),
    (6, """
    ALTER TABLE managed_sensors ADD COLUMN IF NOT EXISTS image_tag TEXT
        NOT NULL DEFAULT 'latest';
    """),
    (7, """
    CREATE TABLE IF NOT EXISTS vt_url_scans (
        url TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        malicious INT DEFAULT 0,
        suspicious INT DEFAULT 0,
        harmless INT DEFAULT 0,
        undetected INT DEFAULT 0,
        permalink TEXT DEFAULT '',
        report_json TEXT DEFAULT '',
        analysis_id TEXT DEFAULT '',
        error TEXT DEFAULT '',
        scanned_at TIMESTAMPTZ DEFAULT now(),
        updated_at TIMESTAMPTZ DEFAULT now());
    """),
    (8, """
    ALTER TABLE ip_intel ADD COLUMN IF NOT EXISTS country_code TEXT
        DEFAULT '';
    ALTER TABLE ip_intel ADD COLUMN IF NOT EXISTS country TEXT
        DEFAULT '';
    ALTER TABLE ip_intel ADD COLUMN IF NOT EXISTS city TEXT DEFAULT '';
    ALTER TABLE ip_intel ADD COLUMN IF NOT EXISTS org TEXT DEFAULT '';
    """),
]


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


class Database:
    def __init__(self, dsn: str):
        self._dsn = dsn
        self._conn = None
        self._lock = asyncio.Lock()
        self._closed = False

    async def connect(self):
        self._conn = await psycopg.AsyncConnection.connect(
            self._dsn, autocommit=False)
        self._closed = False
        await self.migrate()

    async def close(self):
        # Take the lock so in-flight queries finish before the connection
        # is torn down; afterwards the guard fails fast instead of touching
        # a closed libpq handle (use-after-free segfaults the C accel).
        async with self._lock:
            if self._conn is not None:
                await self._conn.close()
                self._conn = None
            self._closed = True

    def _guard(self):
        if self._closed or self._conn is None:
            raise DatabaseClosedError("database is closed")

    async def migrate(self):
        async with self._lock:
            self._guard()
            async with self._conn.cursor() as cur:
                await cur.execute(
                    "CREATE TABLE IF NOT EXISTS schema_version "
                    "(version INT PRIMARY KEY)")
                await cur.execute("SELECT version FROM schema_version")
                have = {row[0] for row in await cur.fetchall()}
                for version, sql in MIGRATIONS:
                    if version in have:
                        continue
                    await cur.execute(sql)
                    await cur.execute(
                        "INSERT INTO schema_version (version) VALUES (%s)",
                        (version,))
                    log.info("applied db migration %d", version)
                log.debug("db migrations current (%d applied)", len(have))
            await self._conn.commit()

    async def reset(self):
        """Delete ALL rows from every data table (testing only).

        Schema and schema_version stay intact, so afterwards the database
        looks like a fresh migrate(). Console users are wiped too —
        recreate one with ``carbide-server --ensure-admin``. Returns the
        truncated table names.
        """
        async with self._lock:
            self._guard()
            async with self._conn.cursor() as cur:
                await cur.execute(
                    "SELECT tablename FROM pg_tables "
                    "WHERE schemaname = 'public' "
                    "AND tablename <> 'schema_version' "
                    "ORDER BY tablename")
                tables = [row[0] for row in await cur.fetchall()]
                if tables:
                    quoted = ", ".join(
                        '"%s"' % t.replace('"', '""') for t in tables)
                    await cur.execute(
                        f"TRUNCATE {quoted} RESTART IDENTITY CASCADE")
            await self._conn.commit()
            return tables

    # Session-keyed evidence tables. clear_sessions() wipes these and
    # nothing else: users, settings, VT caches, intel, affinities,
    # snapshots, and sensor records survive. Blob bytes stay on disk
    # (quota-capped store, same as reset()).
    SESSION_TABLES = ("transcripts", "session_files", "auth_attempts",
                      "diffs", "reports", "squid_hits", "sessions")

    async def clear_sessions(self):
        """Delete all sessions and their evidence (console action).

        Returns per-table row counts. Live sessions re-insert rows on
        their next event; containers and affinities are untouched.
        """
        counts = {}
        async with self._lock:
            self._guard()
            async with self._conn.cursor() as cur:
                for table in self.SESSION_TABLES:
                    await cur.execute(
                        f'DELETE FROM "{table}"')
                    counts[table] = cur.rowcount
            await self._conn.commit()
        return counts

    async def _exec(self, sql, params=(), fetch=None):
        async with self._lock:
            self._guard()
            async with self._conn.cursor() as cur:
                await cur.execute(sql, params)
                result = None
                if fetch == "one":
                    result = await cur.fetchone()
                elif fetch == "all":
                    result = await cur.fetchall()
            await self._conn.commit()
            return result

    # -- idempotency ---------------------------------------------------
    async def claim_record(self, record_id: str) -> bool:
        """True when this record was never applied before."""
        async with self._lock:
            self._guard()
            async with self._conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO applied_records (record_id) VALUES (%s) "
                    "ON CONFLICT DO NOTHING RETURNING record_id",
                    (record_id,))
                row = await cur.fetchone()
            await self._conn.commit()
            return row is not None

    # -- sensors / affinity --------------------------------------------
    async def note_sensor(self, sensor_id: str):
        await self._exec(
            "INSERT INTO sensors (sensor_id) VALUES (%s) "
            "ON CONFLICT (sensor_id) DO UPDATE SET last_seen = now()",
            (sensor_id,))

    async def get_affinity(self, sensor_id: str, ip: str):
        row = await self._exec(
            "SELECT sensor_id, attacker_ip, container_id, ssh_port, "
            "ssh_password, container_ip, has_activity, created_at, "
            "last_session_end FROM affinities "
            "WHERE sensor_id = %s AND attacker_ip = %s",
            (sensor_id, ip), fetch="one")
        return self._affinity_row(row) if row else None

    async def get_affinity_by_container_ip(self, container_ip: str):
        row = await self._exec(
            "SELECT sensor_id, attacker_ip, container_id, ssh_port, "
            "ssh_password, container_ip, has_activity, created_at, "
            "last_session_end FROM affinities WHERE container_ip = %s "
            "ORDER BY created_at DESC LIMIT 1",
            (container_ip,), fetch="one")
        return self._affinity_row(row) if row else None

    @staticmethod
    def _affinity_row(row):
        keys = ("sensor_id", "attacker_ip", "container_id", "ssh_port",
                "ssh_password", "container_ip", "has_activity",
                "created_at", "last_session_end")
        return dict(zip(keys, row))

    async def set_affinity(self, sensor_id: str, ip: str, container_id: str,
                           ssh_port: int, ssh_password: str,
                           container_ip: str):
        await self._exec(
            "INSERT INTO affinities (sensor_id, attacker_ip, container_id, "
            "ssh_port, ssh_password, container_ip) VALUES (%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (sensor_id, attacker_ip) DO UPDATE SET "
            "container_id = EXCLUDED.container_id, "
            "ssh_port = EXCLUDED.ssh_port, "
            "ssh_password = EXCLUDED.ssh_password, "
            "container_ip = EXCLUDED.container_ip",
            (sensor_id, ip, container_id, ssh_port, ssh_password,
             container_ip))

    async def set_affinity_activity(self, sensor_id: str, ip: str,
                                    active: bool):
        await self._exec(
            "UPDATE affinities SET has_activity = %s "
            "WHERE sensor_id = %s AND attacker_ip = %s",
            (active, sensor_id, ip))

    async def touch_affinity_end(self, sensor_id: str, ip: str):
        await self._exec(
            "UPDATE affinities SET last_session_end = now() "
            "WHERE sensor_id = %s AND attacker_ip = %s",
            (sensor_id, ip))

    async def list_affinities(self):
        rows = await self._exec(
            "SELECT sensor_id, attacker_ip, container_id, ssh_port, "
            "ssh_password, container_ip, has_activity, created_at, "
            "last_session_end FROM affinities ORDER BY last_session_end "
            "NULLS FIRST", fetch="all")
        return [self._affinity_row(r) for r in rows]

    async def delete_affinity(self, sensor_id: str, ip: str):
        await self._exec(
            "DELETE FROM affinities WHERE sensor_id = %s AND attacker_ip = %s",
            (sensor_id, ip))

    async def ports_in_use(self) -> set:
        rows = await self._exec("SELECT ssh_port FROM affinities",
                                fetch="all")
        return {r[0] for r in rows}

    # -- sessions ------------------------------------------------------
    async def ensure_session(self, session_id: str, sensor_id: str, ip: str):
        await self._exec(
            "INSERT INTO sessions (session_id, sensor_id, attacker_ip) "
            "VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
            (session_id, sensor_id, ip))

    async def set_session_started(self, session_id: str, username: str, at,
                                  ip=None):
        if ip is None:
            await self._exec(
                "UPDATE sessions SET username = %s, started_at = %s "
                "WHERE session_id = %s", (username, at, session_id))
        else:
            await self._exec(
                "UPDATE sessions SET username = %s, started_at = %s, "
                "attacker_ip = %s WHERE session_id = %s",
                (username, at, ip, session_id))

    async def set_session_container(self, session_id: str, container_id: str,
                                    fresh: bool):
        await self._exec(
            "UPDATE sessions SET container_id = %s, fresh = %s "
            "WHERE session_id = %s", (container_id, fresh, session_id))

    async def set_session_end(self, session_id: str, at, reason: str):
        await self._exec(
            "UPDATE sessions SET ended_at = %s, end_reason = %s "
            "WHERE session_id = %s", (at, reason, session_id))

    async def get_session(self, session_id: str):
        return await self._exec(
            "SELECT session_id, sensor_id, attacker_ip, username, "
            "container_id, fresh, over_quota, started_at, ended_at, "
            "end_reason FROM sessions WHERE session_id = %s",
            (session_id,), fetch="one")

    async def latest_open_session(self, sensor_id: str, ip: str):
        return await self._exec(
            "SELECT session_id FROM sessions WHERE sensor_id = %s AND "
            "attacker_ip = %s AND ended_at IS NULL "
            "ORDER BY started_at DESC NULLS LAST LIMIT 1",
            (sensor_id, ip), fetch="one")

    async def latest_session(self, sensor_id: str, ip: str):
        return await self._exec(
            "SELECT session_id FROM sessions WHERE sensor_id = %s AND "
            "attacker_ip = %s ORDER BY started_at DESC NULLS LAST LIMIT 1",
            (sensor_id, ip), fetch="one")

    async def add_auth_attempt(self, session_id, sensor_id, username,
                               password, accepted, matched, at):
        await self._exec(
            "INSERT INTO auth_attempts (session_id, sensor_id, username, "
            "password, accepted, matched_list, at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (session_id, sensor_id, username, password, accepted,
             matched, at))

    async def add_transcript(self, session_id, channel, direction, stream,
                             seq, data: bytes, at):
        await self._exec(
            "INSERT INTO transcripts (session_id, channel, direction, "
            "stream, seq, data, at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (session_id, channel, direction, stream, seq, data, at))

    async def session_has_content(self, session_id: str) -> bool:
        row = await self._exec(
            "SELECT 1 FROM transcripts WHERE session_id = %s LIMIT 1",
            (session_id,), fetch="one")
        if row:
            return True
        row = await self._exec(
            "SELECT 1 FROM session_files WHERE session_id = %s LIMIT 1",
            (session_id,), fetch="one")
        return row is not None

    async def session_byte_count(self, session_id: str) -> int:
        row = await self._exec(
            "SELECT COALESCE(SUM(octet_length(data)), 0) FROM transcripts "
            "WHERE session_id = %s", (session_id,), fetch="one")
        total = row[0] if row else 0
        row = await self._exec(
            "SELECT COALESCE(SUM(size), 0) FROM session_files "
            "WHERE session_id = %s", (session_id,), fetch="one")
        return total + (row[0] if row else 0)

    async def set_session_over_quota(self, session_id: str):
        await self._exec(
            "UPDATE sessions SET over_quota = TRUE WHERE session_id = %s",
            (session_id,))

    # -- blobs / files / diffs / reports -------------------------------
    async def add_blob(self, sha: str, path: str, size: int):
        await self._exec(
            "INSERT INTO blobs (sha256, path, size) VALUES (%s,%s,%s) "
            "ON CONFLICT DO NOTHING", (sha, path, size))

    async def get_blob(self, sha: str):
        return await self._exec(
            "SELECT sha256, path, size FROM blobs WHERE sha256 = %s",
            (sha,), fetch="one")

    async def add_session_file(self, session_id, name, sha, size, at,
                               origin="sensor"):
        # origin: 'sensor' (attacker-copied scp/sftp evidence, VT-scanned)
        # or 'forensics' (diff-collected container files, never scanned).
        await self._exec(
            "INSERT INTO session_files (session_id, name, blob_sha, size, "
            "at, origin) VALUES (%s,%s,%s,%s,%s,%s)",
            (session_id, name, sha, size, at, origin))

    async def add_diff_rows(self, session_id, rows):
        for path, kind in rows:
            await self._exec(
                "INSERT INTO diffs (session_id, path, kind) "
                "VALUES (%s,%s,%s)", (session_id, path, kind))

    async def get_diff_rows(self, session_id):
        return await self._exec(
            "SELECT path, kind FROM diffs WHERE session_id = %s ORDER BY "
            "path", (session_id,), fetch="all")

    async def save_report(self, session_id, markdown: str, js: str, at):
        await self._exec(
            "INSERT INTO reports (session_id, markdown, json, at) "
            "VALUES (%s,%s,%s,%s) ON CONFLICT (session_id) DO UPDATE SET "
            "markdown = EXCLUDED.markdown, json = EXCLUDED.json, "
            "at = EXCLUDED.at",
            (session_id, markdown, js, at))

    async def get_report(self, session_id):
        return await self._exec(
            "SELECT markdown, json FROM reports WHERE session_id = %s",
            (session_id,), fetch="one")

    # -- snapshots / squid ---------------------------------------------
    async def add_snapshot(self, sensor_id, ip, container_id, image):
        await self._exec(
            "INSERT INTO snapshots (sensor_id, attacker_ip, container_id, "
            "image) VALUES (%s,%s,%s,%s)",
            (sensor_id, ip, container_id, image))

    async def list_snapshots(self, sensor_id, ip):
        return await self._exec(
            "SELECT image, created_at FROM snapshots "
            "WHERE sensor_id = %s AND attacker_ip = %s "
            "ORDER BY created_at", (sensor_id, ip), fetch="all")

    async def delete_snapshot(self, image: str):
        await self._exec("DELETE FROM snapshots WHERE image = %s", (image,))

    async def add_squid_hit(self, session_id, sensor_id, container_ip, at,
                            method, url, status, size, mime):
        await self._exec(
            "INSERT INTO squid_hits (session_id, sensor_id, container_ip, "
            "at, method, url, status, bytes, mime) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (session_id, sensor_id, container_ip, at, method, url,
             status, size, mime))

    # -- console reads -------------------------------------------------
    @staticmethod
    def _order_by(allow: dict, sort: str, descending: bool,
                  default: str, default_desc: bool, tiebreak: str) -> str:
        """ORDER BY from an allowlist map (the SQL-injection boundary:
        only fixed column names ever reach the query)."""
        if sort not in allow:
            sort, descending = default, default_desc
        col, nulls_last = allow[sort]
        direction = "DESC" if descending else "ASC"
        nulls = " NULLS LAST" if nulls_last else ""
        return f"ORDER BY {col} {direction}{nulls}, {tiebreak}"

    async def list_sensors(self):
        return await self._exec(
            "SELECT sensor_id, first_seen, last_seen FROM sensors "
            "ORDER BY last_seen DESC NULLS LAST", fetch="all")

    _SESSION_SORTS = {
        "session_id": ("session_id", False),
        "sensor_id": ("sensor_id", False),
        "attacker_ip": ("attacker_ip", False),
        "username": ("username", False),
        "container_id": ("container_id", False),
        "started_at": ("started_at", True),
        "ended_at": ("ended_at", True),
    }

    async def list_sessions(self, sensor_id=None, ip=None, open_only=False,
                            require_container=False,
                            limit=100, offset=0, sort="started_at",
                            descending=True):
        conds, params = [], []
        if sensor_id:
            conds.append("sensor_id = %s")
            params.append(sensor_id)
        if ip:
            conds.append("attacker_ip = %s")
            params.append(ip)
        if open_only:
            conds.append("ended_at IS NULL")
        if require_container:
            # Unattached sessions carry '' (the column default), and old
            # rows may carry NULL — exclude both.
            conds.append("container_id IS NOT NULL AND container_id <> ''")
        where = f"WHERE {' AND '.join(conds)}" if conds else ""
        params.extend([limit, offset])
        order = self._order_by(self._SESSION_SORTS, sort, descending,
                               "started_at", True, "session_id")
        return await self._exec(
            "SELECT session_id, sensor_id, attacker_ip, username, "
            "container_id, fresh, over_quota, started_at, ended_at, "
            f"end_reason FROM sessions {where} {order} "
            "LIMIT %s OFFSET %s", tuple(params), fetch="all")

    async def get_transcript(self, session_id: str, after_id: int = 0,
                             limit: int = 500):
        return await self._exec(
            "SELECT id, channel, direction, stream, seq, data, at "
            "FROM transcripts WHERE session_id = %s AND id > %s "
            "ORDER BY id LIMIT %s",
            (session_id, after_id, limit), fetch="all")

    async def list_session_files(self, session_id: str):
        return await self._exec(
            "SELECT id, name, blob_sha, size, at FROM session_files "
            "WHERE session_id = %s ORDER BY id", (session_id,),
            fetch="all")

    async def get_session_file(self, file_id: int):
        return await self._exec(
            "SELECT id, session_id, name, blob_sha, size, at "
            "FROM session_files WHERE id = %s", (file_id,),
            fetch="one")

    _ATTEMPT_SORTS = {
        "id": ("id", False),
        "at": ("at", False),
        "sensor_id": ("sensor_id", False),
        "username": ("username", False),
        "password": ("password", False),
        "accepted": ("accepted", False),
    }

    async def list_auth_attempts(self, session_id=None, sensor_id=None,
                                 username=None, accepted=None,
                                 limit=200, offset=0, sort="id",
                                 descending=True):
        conds, params = [], []
        if session_id:
            conds.append("session_id = %s")
            params.append(session_id)
        if sensor_id:
            conds.append("sensor_id = %s")
            params.append(sensor_id)
        if username:
            conds.append("username = %s")
            params.append(username)
        if accepted is not None:
            conds.append("accepted = %s")
            params.append(accepted)
        where = f"WHERE {' AND '.join(conds)}" if conds else ""
        params.extend([limit, offset])
        order = self._order_by(self._ATTEMPT_SORTS, sort, descending,
                               "id", True, "id DESC")
        return await self._exec(
            "SELECT id, session_id, sensor_id, username, password, "
            "accepted, matched_list, at "
            f"FROM auth_attempts {where} {order} "
            "LIMIT %s OFFSET %s", tuple(params), fetch="all")

    async def list_squid_hits(self, session_id=None, sensor_id=None,
                              limit=200, offset=0):
        conds, params = [], []
        if session_id:
            conds.append("session_id = %s")
            params.append(session_id)
        if sensor_id:
            conds.append("sensor_id = %s")
            params.append(sensor_id)
        where = f"WHERE {' AND '.join(conds)}" if conds else ""
        params.extend([limit, offset])
        return await self._exec(
            "SELECT id, session_id, sensor_id, container_ip, at, method, "
            "url, status, bytes, mime "
            f"FROM squid_hits {where} ORDER BY id DESC LIMIT %s OFFSET %s",
            tuple(params), fetch="all")

    async def get_squid_hit(self, hit_id: int):
        row = await self._exec(
            "SELECT id, session_id, sensor_id, container_ip, at, method, "
            "url, status, bytes, mime "
            "FROM squid_hits WHERE id = %s", (hit_id,), fetch="one")
        return row

    async def list_snapshots_all(self, sensor_id=None, limit=200):
        if sensor_id:
            return await self._exec(
                "SELECT sensor_id, attacker_ip, container_id, image, "
                "created_at FROM snapshots WHERE sensor_id = %s "
                "ORDER BY created_at DESC LIMIT %s",
                (sensor_id, limit), fetch="all")
        return await self._exec(
            "SELECT sensor_id, attacker_ip, container_id, image, "
            "created_at FROM snapshots ORDER BY created_at DESC LIMIT %s",
            (limit,), fetch="all")

    async def count_open_sessions(self) -> int:
        row = await self._exec(
            "SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL",
            fetch="one")
        return row[0] if row else 0

    async def count_sessions_since(self, at) -> int:
        row = await self._exec(
            "SELECT COUNT(*) FROM sessions WHERE started_at >= %s",
            (at,), fetch="one")
        return row[0] if row else 0

    async def count_affinities(self) -> int:
        row = await self._exec("SELECT COUNT(*) FROM affinities",
                               fetch="one")
        return row[0] if row else 0

    async def count_auth_since(self, at) -> int:
        row = await self._exec(
            "SELECT COUNT(*) FROM auth_attempts WHERE at >= %s",
            (at,), fetch="one")
        return row[0] if row else 0

    # -- console users / sessions --------------------------------------
    @staticmethod
    def _web_user_row(row):
        keys = ("id", "username", "pw_hash", "created_at", "disabled")
        return dict(zip(keys, row))

    async def create_web_user(self, username: str, pw_hash: str) -> int:
        async with self._lock:
            self._guard()
            async with self._conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO web_users (username, pw_hash) "
                    "VALUES (%s, %s) RETURNING id",
                    (username, pw_hash))
                row = await cur.fetchone()
            await self._conn.commit()
            return row[0]

    async def get_web_user_by_name(self, username: str):
        row = await self._exec(
            "SELECT id, username, pw_hash, created_at, disabled "
            "FROM web_users WHERE username = %s", (username,),
            fetch="one")
        return self._web_user_row(row) if row else None

    async def get_web_user(self, user_id: int):
        row = await self._exec(
            "SELECT id, username, pw_hash, created_at, disabled "
            "FROM web_users WHERE id = %s", (user_id,), fetch="one")
        return self._web_user_row(row) if row else None

    async def list_web_users(self):
        rows = await self._exec(
            "SELECT id, username, pw_hash, created_at, disabled "
            "FROM web_users ORDER BY username", fetch="all")
        return [self._web_user_row(r) for r in rows]

    async def set_web_user_disabled(self, user_id: int, disabled: bool):
        await self._exec(
            "UPDATE web_users SET disabled = %s WHERE id = %s",
            (disabled, user_id))

    async def set_web_user_password(self, user_id: int, pw_hash: str):
        await self._exec(
            "UPDATE web_users SET pw_hash = %s WHERE id = %s",
            (pw_hash, user_id))

    async def create_web_session(self, token_sha: str, user_id: int,
                                 expires_at):
        await self._exec(
            "INSERT INTO web_sessions (token_sha, user_id, expires_at) "
            "VALUES (%s, %s, %s)", (token_sha, user_id, expires_at))

    async def get_web_session(self, token_sha: str):
        return await self._exec(
            "SELECT s.token_sha, s.user_id, s.expires_at, u.username, "
            "u.disabled FROM web_sessions s JOIN web_users u "
            "ON u.id = s.user_id WHERE s.token_sha = %s",
            (token_sha,), fetch="one")

    async def delete_web_session(self, token_sha: str):
        await self._exec(
            "DELETE FROM web_sessions WHERE token_sha = %s", (token_sha,))

    async def delete_expired_web_sessions(self):
        await self._exec(
            "DELETE FROM web_sessions WHERE expires_at < now()")

    # -- managed sensors ------------------------------------------------
    _MANAGED_COLS = ("sensor_id", "ssh_host", "ssh_port", "ssh_user",
                     "remote_dir", "listen_addr", "listen_port",
                     "server_host", "server_port", "auth_passwords",
                     "accept_probability", "notes", "image_tag",
                     "updated_at")

    @classmethod
    def _managed_row(cls, row):
        return dict(zip(cls._MANAGED_COLS, row))

    async def upsert_managed_sensor(self, sensor_id: str, ssh_host: str,
                                    ssh_port: int = 22, ssh_user: str = "",
                                    remote_dir: str = "",
                                    listen_addr: str = "0.0.0.0",
                                    listen_port: int = 2222,
                                    server_host: str = "",
                                    server_port: int = 8440,
                                    auth_passwords: str = "[]",
                                    accept_probability: float = 0.05,
                                    notes: str = "",
                                    image_tag: str = "latest"):
        await self._exec(
            "INSERT INTO managed_sensors (sensor_id, ssh_host, ssh_port, "
            "ssh_user, remote_dir, listen_addr, listen_port, server_host, "
            "server_port, auth_passwords, accept_probability, notes, "
            "image_tag) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (sensor_id) DO UPDATE SET ssh_host = EXCLUDED.ssh_host, "
            "ssh_port = EXCLUDED.ssh_port, ssh_user = EXCLUDED.ssh_user, "
            "remote_dir = EXCLUDED.remote_dir, "
            "listen_addr = EXCLUDED.listen_addr, "
            "listen_port = EXCLUDED.listen_port, "
            "server_host = EXCLUDED.server_host, "
            "server_port = EXCLUDED.server_port, "
            "auth_passwords = EXCLUDED.auth_passwords, "
            "accept_probability = EXCLUDED.accept_probability, "
            "notes = EXCLUDED.notes, image_tag = EXCLUDED.image_tag, "
            "updated_at = now()",
            (sensor_id, ssh_host, ssh_port, ssh_user, remote_dir,
             listen_addr, listen_port, server_host, server_port,
             auth_passwords, accept_probability, notes, image_tag))

    async def get_managed_sensor(self, sensor_id: str):
        row = await self._exec(
            "SELECT sensor_id, ssh_host, ssh_port, ssh_user, remote_dir, "
            "listen_addr, listen_port, server_host, server_port, "
            "auth_passwords, accept_probability, notes, image_tag, "
            "updated_at "
            "FROM managed_sensors WHERE sensor_id = %s", (sensor_id,),
            fetch="one")
        return self._managed_row(row) if row else None

    async def list_managed_sensors(self):
        rows = await self._exec(
            "SELECT sensor_id, ssh_host, ssh_port, ssh_user, remote_dir, "
            "listen_addr, listen_port, server_host, server_port, "
            "auth_passwords, accept_probability, notes, image_tag, "
            "updated_at "
            "FROM managed_sensors ORDER BY sensor_id", fetch="all")
        return [self._managed_row(r) for r in rows]

    async def delete_managed_sensor(self, sensor_id: str):
        await self._exec(
            "DELETE FROM managed_sensors WHERE sensor_id = %s",
            (sensor_id,))

    # -- virustotal -----------------------------------------------------
    _VT_COLS = ("sha256", "status", "malicious", "suspicious", "harmless",
                "undetected", "permalink", "report_json", "analysis_id",
                "error", "scanned_at", "updated_at")

    @classmethod
    def _vt_row(cls, row):
        return dict(zip(cls._VT_COLS, row))

    async def get_vt_scan(self, sha: str):
        row = await self._exec(
            "SELECT sha256, status, malicious, suspicious, harmless, "
            "undetected, permalink, report_json, analysis_id, error, "
            "scanned_at, updated_at FROM vt_scans WHERE sha256 = %s",
            (sha,), fetch="one")
        return self._vt_row(row) if row else None

    async def get_vt_scans(self, shas) -> dict:
        """Batch verdicts keyed by sha (console file lists)."""
        shas = list(dict.fromkeys(s for s in shas if s))
        if not shas:
            return {}
        rows = await self._exec(
            "SELECT sha256, status, malicious, suspicious, harmless, "
            "undetected, permalink, report_json, analysis_id, error, "
            "scanned_at, updated_at FROM vt_scans WHERE sha256 = ANY(%s)",
            (shas,), fetch="all")
        return {row[0]: self._vt_row(row) for row in rows}

    async def save_vt_scan(self, sha: str, status: str, malicious: int = 0,
                           suspicious: int = 0, harmless: int = 0,
                           undetected: int = 0, permalink: str = "",
                           report_json: str = "", analysis_id: str = "",
                           error: str = ""):
        await self._exec(
            "INSERT INTO vt_scans (sha256, status, malicious, suspicious, "
            "harmless, undetected, permalink, report_json, analysis_id, "
            "error) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (sha256) DO UPDATE SET status = EXCLUDED.status, "
            "malicious = EXCLUDED.malicious, "
            "suspicious = EXCLUDED.suspicious, "
            "harmless = EXCLUDED.harmless, "
            "undetected = EXCLUDED.undetected, "
            "permalink = EXCLUDED.permalink, "
            "report_json = EXCLUDED.report_json, "
            "analysis_id = EXCLUDED.analysis_id, "
            "error = EXCLUDED.error, updated_at = now()",
            (sha, status, malicious, suspicious, harmless, undetected,
             permalink, report_json, analysis_id, error))

    _VT_URL_COLS = ("url", "status", "malicious", "suspicious",
                    "harmless", "undetected", "permalink", "report_json",
                    "analysis_id", "error", "scanned_at", "updated_at")

    @classmethod
    def _vt_url_row(cls, row):
        return dict(zip(cls._VT_URL_COLS, row))

    async def get_vt_url_scan(self, url: str):
        row = await self._exec(
            "SELECT url, status, malicious, suspicious, harmless, "
            "undetected, permalink, report_json, analysis_id, error, "
            "scanned_at, updated_at FROM vt_url_scans WHERE url = %s",
            (url,), fetch="one")
        return self._vt_url_row(row) if row else None

    async def get_vt_url_scans(self, urls) -> dict:
        """Batch URL verdicts keyed by url (console hit lists)."""
        urls = list(dict.fromkeys(u for u in urls if u))
        if not urls:
            return {}
        rows = await self._exec(
            "SELECT url, status, malicious, suspicious, harmless, "
            "undetected, permalink, report_json, analysis_id, error, "
            "scanned_at, updated_at FROM vt_url_scans "
            "WHERE url = ANY(%s)",
            (urls,), fetch="all")
        return {row[0]: self._vt_url_row(row) for row in rows}

    async def save_vt_url_scan(self, url: str, status: str,
                               malicious: int = 0, suspicious: int = 0,
                               harmless: int = 0, undetected: int = 0,
                               permalink: str = "", report_json: str = "",
                               analysis_id: str = "", error: str = ""):
        await self._exec(
            "INSERT INTO vt_url_scans (url, status, malicious, suspicious, "
            "harmless, undetected, permalink, report_json, analysis_id, "
            "error) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (url) DO UPDATE SET status = EXCLUDED.status, "
            "malicious = EXCLUDED.malicious, "
            "suspicious = EXCLUDED.suspicious, "
            "harmless = EXCLUDED.harmless, "
            "undetected = EXCLUDED.undetected, "
            "permalink = EXCLUDED.permalink, "
            "report_json = EXCLUDED.report_json, "
            "analysis_id = EXCLUDED.analysis_id, "
            "error = EXCLUDED.error, updated_at = now()",
            (url, status, malicious, suspicious, harmless, undetected,
             permalink, report_json, analysis_id, error))

    async def pending_vt_urls(self, limit: int):
        """Submitted URL analyses awaiting a poll (oldest first)."""
        return await self._exec(
            "SELECT url, analysis_id FROM vt_url_scans "
            "WHERE status = 'pending' AND analysis_id <> '' "
            "ORDER BY updated_at LIMIT %s",
            (limit,), fetch="all")

    async def vt_candidates(self, limit: int, cutoff):
        """Sensor-captured files (scp/sftp evidence) never scanned;
        pending analyses (re-polled, never re-uploaded); and rows older
        than cutoff (errors and stale successes alike are due for a
        re-check). Forensics-collected container files (origin =
        'forensics': /etc/passwd-style diff captures) are deliberately
        excluded — they are evidence, not attacker uploads."""
        return await self._exec(
            "SELECT f.blob_sha, MAX(f.size) AS size FROM session_files f "
            "LEFT JOIN vt_scans v ON v.sha256 = f.blob_sha "
            "WHERE f.blob_sha <> '' AND f.origin = 'sensor' "
            "AND (v.sha256 IS NULL "
            "OR v.status = 'pending' OR v.updated_at < %s) "
            "GROUP BY f.blob_sha ORDER BY MIN(f.at) LIMIT %s",
            (cutoff, limit), fetch="all")

    async def claim_vt_quota(self, day, cap: int):
        """Atomically consume one daily VT request if under cap; True
        when the caller may proceed."""
        row = await self._exec(
            "INSERT INTO vt_quota (day, used) VALUES (%s, 1) "
            "ON CONFLICT (day) DO UPDATE SET used = vt_quota.used + 1 "
            "WHERE vt_quota.used < %s RETURNING used",
            (day, cap), fetch="one")
        return row is not None

    async def vt_quota_used(self, day) -> int:
        row = await self._exec(
            "SELECT used FROM vt_quota WHERE day = %s", (day,),
            fetch="one")
        return row[0] if row else 0

    # -- ip intel --------------------------------------------------------
    _INTEL_COLS = ("attacker_ip", "rdns", "status", "open_ports",
                   "raw_xml", "error", "scanned_at", "country_code",
                   "country", "city", "org")

    @classmethod
    def _intel_row(cls, row):
        return dict(zip(cls._INTEL_COLS, row))

    async def get_ip_intel(self, ip: str):
        row = await self._exec(
            "SELECT attacker_ip, rdns, status, open_ports, raw_xml, error, "
            "scanned_at, country_code, country, city, org "
            "FROM ip_intel WHERE attacker_ip = %s", (ip,),
            fetch="one")
        return self._intel_row(row) if row else None

    async def get_ip_intel_many(self, ips) -> dict:
        """Batch intel rows keyed by ip (console enrichment)."""
        ips = list(dict.fromkeys(i for i in ips if i))
        if not ips:
            return {}
        rows = await self._exec(
            "SELECT attacker_ip, rdns, status, open_ports, raw_xml, error, "
            "scanned_at, country_code, country, city, org "
            "FROM ip_intel WHERE attacker_ip = ANY(%s)",
            (ips,), fetch="all")
        return {row[0]: self._intel_row(row) for row in rows}

    async def save_ip_intel(self, ip: str, rdns: str = "", status: str = "ok",
                            open_ports: str = "[]", raw_xml: str = "",
                            error: str = "", country_code: str = "",
                            country: str = "", city: str = "",
                            org: str = ""):
        await self._exec(
            "INSERT INTO ip_intel (attacker_ip, rdns, status, open_ports, "
            "raw_xml, error, country_code, country, city, org) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (attacker_ip) DO UPDATE SET rdns = EXCLUDED.rdns, "
            "status = EXCLUDED.status, open_ports = EXCLUDED.open_ports, "
            "raw_xml = EXCLUDED.raw_xml, error = EXCLUDED.error, "
            "country_code = EXCLUDED.country_code, "
            "country = EXCLUDED.country, city = EXCLUDED.city, "
            "org = EXCLUDED.org, scanned_at = now()",
            (ip, rdns, status, open_ports, raw_xml, error, country_code,
             country, city, org))

    async def ips_needing_scan(self, limit: int, cutoff):
        """Attacker IPs seen in sessions with no (or stale) intel row."""
        rows = await self._exec(
            "SELECT DISTINCT s.attacker_ip FROM sessions s "
            "LEFT JOIN ip_intel i ON i.attacker_ip = s.attacker_ip "
            "WHERE s.attacker_ip <> '' "
            "AND (i.attacker_ip IS NULL OR i.scanned_at < %s) "
            "LIMIT %s", (cutoff, limit), fetch="all")
        return [row[0] for row in rows]

    # -- server settings (console-editable) -------------------------------
    async def get_setting(self, key: str):
        row = await self._exec(
            "SELECT value FROM server_settings WHERE key = %s", (key,),
            fetch="one")
        return row[0] if row else None

    async def set_setting(self, key: str, value: str):
        await self._exec(
            "INSERT INTO server_settings (key, value) VALUES (%s, %s) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, "
            "updated_at = now()",
            (key, value))

    async def delete_setting(self, key: str):
        await self._exec(
            "DELETE FROM server_settings WHERE key = %s", (key,))

    # -- attacker overview (console) --------------------------------------
    _ATTACKER_SORTS = {
        "attacker_ip": ("attacker_ip", False),
        "sessions": ("sessions", False),
        "last_seen": ("last_seen", True),
        "files": ("files", False),
        "malicious": ("malicious", False),
        "intel": ("intel", False),
    }

    async def list_attackers(self, limit=200, offset=0, sort="last_seen",
                             descending=True):
        order = self._order_by(self._ATTACKER_SORTS, sort, descending,
                               "last_seen", True, "attacker_ip")
        return await self._exec(
            "SELECT s.attacker_ip, COUNT(DISTINCT s.session_id) AS sessions, "
            "MAX(s.started_at) AS last_seen, "
            "COUNT(DISTINCT f.id) AS files, "
            "COUNT(DISTINCT CASE WHEN v.malicious > 0 THEN f.id END) "
            "AS malicious, i.status AS intel "
            "FROM sessions s "
            "LEFT JOIN session_files f ON f.session_id = s.session_id "
            "LEFT JOIN vt_scans v ON v.sha256 = f.blob_sha "
            "LEFT JOIN ip_intel i ON i.attacker_ip = s.attacker_ip "
            "WHERE s.attacker_ip <> '' "
            f"GROUP BY s.attacker_ip, i.status {order} LIMIT %s OFFSET %s",
            (limit, offset), fetch="all")

    async def attacker_geo(self):
        """Per-country attacker + session counts for the world map."""
        return await self._exec(
            "SELECT i.country_code, MAX(i.country) AS country, "
            "COUNT(DISTINCT s.attacker_ip) AS attackers, "
            "COUNT(DISTINCT s.session_id) AS sessions "
            "FROM sessions s "
            "JOIN ip_intel i ON i.attacker_ip = s.attacker_ip "
            "WHERE s.attacker_ip <> '' AND i.country_code <> '' "
            "GROUP BY i.country_code "
            "ORDER BY attackers DESC",
            fetch="all")

    async def list_files_by_ip(self, ip: str, limit=500):
        return await self._exec(
            "SELECT f.id, f.session_id, f.name, f.blob_sha, f.size, f.at, "
            "v.status, v.malicious, v.suspicious, v.permalink "
            "FROM session_files f JOIN sessions s "
            "ON s.session_id = f.session_id "
            "LEFT JOIN vt_scans v ON v.sha256 = f.blob_sha "
            "WHERE s.attacker_ip = %s ORDER BY f.id DESC LIMIT %s",
            (ip, limit), fetch="all")

    _FILE_SORTS = {
        "name": ("f.name", False),
        "session_id": ("f.session_id", False),
        "sensor_id": ("s.sensor_id", False),
        "attacker_ip": ("s.attacker_ip", False),
        "size": ("f.size", False),
        "at": ("f.at", False),
        "verdict": ("v.status", True),
    }

    async def list_all_files(self, sensor_id=None, ip=None, verdict=None,
                             limit=100, offset=0, sort="at",
                             descending=True):
        """Every captured file with its session + VT verdict (Files page).

        verdict is a vt_scans status or "unscanned" (no scan row); any
        other value is ignored.
        """
        conds, params = [], []
        if sensor_id:
            conds.append("s.sensor_id = %s")
            params.append(sensor_id)
        if ip:
            conds.append("s.attacker_ip = %s")
            params.append(ip)
        if verdict == "unscanned":
            conds.append("v.status IS NULL")
        elif verdict in ("malicious", "suspicious", "clean", "pending",
                         "skipped", "error"):
            conds.append("v.status = %s")
            params.append(verdict)
        where = f"WHERE {' AND '.join(conds)}" if conds else ""
        params.extend([limit, offset])
        order = self._order_by(self._FILE_SORTS, sort, descending,
                               "at", True, "f.id DESC")
        return await self._exec(
            "SELECT f.id, f.session_id, s.sensor_id, s.attacker_ip, "
            "f.name, f.blob_sha, f.size, f.at, "
            "v.status, v.malicious, v.suspicious, v.permalink "
            "FROM session_files f JOIN sessions s "
            "ON s.session_id = f.session_id "
            "LEFT JOIN vt_scans v ON v.sha256 = f.blob_sha "
            f"{where} {order} LIMIT %s OFFSET %s",
            tuple(params), fetch="all")
