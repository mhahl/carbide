# Carbide — SSH honeypot fleet

Carbide mimics SSH servers to observe attackers. Lightweight **sensors** take
the SSH connections, decide who gets in, and proxy accepted sessions to
per-attacker containers on a central **server**, which records everything,
keeps Postgres metadata plus an NFS blob store, and writes forensic reports.

Decisions governing this project live in [DECISIONS.md](DECISIONS.md) (Final).

## Layout

- `src/carbide/sensor/` — `carbide-sensor`: SSH front door, D2 auth, session
  proxy/recording, durable spool, server link.
- `src/carbide/server/` — `carbide-server`: control API, affinity pool,
  forensics, eviction, Squid-log ingest, Postgres.
- `src/carbide/common/` — config, protocol, blob store (shared by both roles).
- `tests/` — unit suite (`python -m unittest discover -s tests`) plus live
  integration tests (see below).
- `image/` — honeypot container definition (Alpine + sshd).
- `squid/` — peek-and-splice Squid config and nftables snippet (no MITM).
- `packaging/` — systemd units, example configs, logrotate.
- `deploy/` — Ansible playbooks for server/sensor installs ([guide](deploy/README.md)).
- `docs/` — deployment, analyst guide, abuse runbook, protocol reference.

## Quickstart (single-host trial)

Prerequisites: Python 3.11+, Podman, Postgres, Squid (see
[deployment](docs/deployment.md) for service setup).

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Build the honeypot image and point a server config at Postgres + Podman:

```sh
podman build -t carbide-honeypot:latest image/
cp packaging/config-server.toml.example /tmp/server.toml
cp packaging/config-sensor.toml.example /tmp/sensor.toml
# edit tokens, db_dsn, ports, then:
carbide-server -c /tmp/server.toml &
carbide-sensor -c /tmp/sensor.toml &
ssh -p 2222 root@127.0.0.1   # try passwords; watch the server logs
```

## Configuration

One file per host (`/etc/carbide/config.toml`), `role = "sensor"` or
`"server"`, role-appropriate tables. Start from the files in `packaging/`;
every key is validated with explicit errors on typos, missing values, and
out-of-range numbers.

## Documentation

- [admin-guide](docs/admin-guide.md) — install, configure, operate,
  troubleshoot (start here).
- [analyst-guide](docs/analyst-guide.md) — reading sessions and reports.
- [abuse-runbook](docs/abuse-runbook.md) — egress abuse handling.
- [protocol](docs/protocol.md) — sensor↔server wire reference.
- [deployment](docs/deployment.md) — role checklists (condensed in admin-guide).

## Testing

```sh
python -m unittest discover -s tests          # unit suite (no services)
python -m unittest tests.test_db -v           # postgres-backed tests
CARBIDE_LIVE_TESTS=1 python -m unittest tests.test_live -v  # live E2E
```

`test_db` starts its own throwaway Postgres cluster (`initdb`/`pg_ctl` must
exist). `test_live` is the full two-sensor live E2E (real Podman containers,
Squid, SSH clients; builds `carbide-honeypot:latest` if missing) and is
gated behind `CARBIDE_LIVE_TESTS=1` so the unit suite stays fast. Both skip
cleanly when their prerequisites are missing.

## Evidence model (short version)

- Every SSH connection is a **session**: auth attempts, a timestamped
  transcript of both directions, carved SFTP/SCP files, and Squid hits.
- Every session end (and every eviction) produces a **forensic report**:
  cumulative container diff, changed-file contents, unified diffs, plus a
  committed image **snapshot** (retention-capped).
- Postgres holds metadata and pointers; bulky bytes live content-addressed in
  the blob store; hashes link the two. Start any investigation from one
  `sessions` row — see [analyst-guide](docs/analyst-guide.md).

## Security notes

- Sensors never hold Postgres credentials or Podman access — only a
  per-sensor API token. The server treats all sensor input as untrusted.
- The sensor↔server link is plain TCP: run it over your VPN/private network.
- Containers have no direct egress; web goes through Squid with metadata
  blocks, port restrictions, and body caps. Operating an egress path still
  exposes you to abuse complaints — read [abuse-runbook](docs/abuse-runbook.md)
  before pointing sensors at the internet.
