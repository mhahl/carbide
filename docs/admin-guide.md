# Carbide administrator guide

Sensors take attacker SSH connections and forward evidence; one server runs
containers, Postgres, Squid, and forensics. One config file per host:
`/etc/carbide/config.toml`.

```
attacker -> sensor:2222 (accept?) -> SSH proxy -> container:220xx (server host)
sensor --spool--> server:8440 (API) -> Postgres + blob store + reports
container -80/443-> Squid -> internet (logged, capped)
```

## Components: what and why

| Component | Host | What it does | Why it exists |
|---|---|---|---|
| `carbide-sensor` SSH front door | sensor | asyncssh server, auth policy, per-session proxy to containers | looks like a real server; cheap and disposable |
| auth policy | sensor | allow-listed passwords always in; else one probability roll per username per connection; `max_attempts` cap | D2: deterministic for known-bad, statistical for the rest |
| proxy bridge | sensor | pipes attacker channel to container sshd, records both directions | attacker interacts with a real system, not a script |
| transcript recorder | sensor | every byte in/out + `meta/command` records of exec requests | full session replay from Postgres |
| SCP carver | sensor | parses `scp -t/-f` streams into files, names by `scp` target | uploaded tools captured with destination paths |
| SFTP forwarder | sensor | proxies SFTP, carves up/downloads with full paths | same for SFTP |
| spool + server link | sensor | disk outbox, in-order forward, ack removes; reconnects with backoff | evidence survives VPN/server outages; server dedupes replays |
| server API | server | token-auth JSON-lines TCP: `container_for` + idempotent records | single choke point; treats sensors as untrusted |
| affinity pool | server | one container per (sensor, attacker IP); reuse on reconnect; pre-warmed fresh pool | attacker persistence across sessions; fast handoff |
| forensics | server | on session end: container diff vs `carbide-ref`, file contents, unified diffs, report, snapshot commit | easy per-session "what changed" without manual diffing |
| eviction | server | stops idle-warm containers; TTLs (active 30d / inactive 24h) + 200-container LRU backstop; final archive first | bounds disk/CPU/abuse window automatically |
| Squid tailer | server | tails `access.log`, attributes hits to sessions by container IP | egress visibility without TLS interception |
| Postgres | server | sessions, auth, transcripts, files, diffs, reports, snapshots, squid hits, affinities | metadata + pointers; blobs live on disk |
| blob store | server | `<blob_dir>/<2-hex>/<sha256>`, content-addressed, quota-capped | identical payloads stored once across fleet |
| honeypot image | server | Alpine + sshd + `honey` user; entrypoint sets password, stamps proxy `SetEnv` | real Linux target; unique host keys per container |
| Squid | server | explicit :3128 + transparent :3129/:3130, peek-and-splice TLS (SNI logged, never decrypted) | web egress with logging, ACLs, body caps |
| nftables snippet | server | transparent mode: redirect 80/443 to Squid, DNS-to-resolver-only, drop rest | containers get no direct egress |

## Install: server host

Needs: Fedora/RHEL-like with root. Postgres + Squid may live on other hosts;
adjust addresses accordingly.

```sh
# 1. packages (libpq, NOT psycopg[binary]: its bundled OpenSSL crashes)
dnf install -y python3-pip postgresql-server squid openssl podman \
  openssh-clients libpq logrotate

# 2. carbide itself
pip install /path/to/carbide        # or: pip install -e .  from a checkout

# 3. postgres
postgresql-setup --initdb
systemctl enable --now postgresql
sudo -u postgres psql -c "CREATE USER carbide WITH PASSWORD 'STRONG-PW';"
sudo -u postgres psql -c "CREATE DATABASE carbide OWNER carbide;"
# schema migrates itself at first server start

# 4. container network + honeypot image
podman network create carbide
podman build -t carbide-honeypot:latest /path/to/carbide/image/

# 5. squid
cp /path/to/carbide/squid/squid.conf /etc/squid/squid.conf
# edit the 'acl containers src' line to your container subnet, then:
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=carbide-splice \
  -keyout /etc/squid/splice-dummy.pem -out /etc/squid/splice-dummy.pem
squid -k parse && systemctl enable --now squid

# 6a. egress: transparent mode (review the snippet first!)
# edit interface/subnet/$RESOLVER, then: nft -f squid/nftables.conf.snippet
# 6b. egress: explicit mode instead -> set [squid] mode + explicit_proxy,
#     no firewall changes needed (containers get no DNS at all)

# 7. blob store (local disk or NFS mount)
mkdir -p /var/lib/carbide/blobs
# NFS: mount -t nfs nas:/export/carbide-blobs /var/lib/carbide/blobs

# 8. config + service + logrotate
mkdir -p /etc/carbide
cp /path/to/carbide/packaging/config-server.toml.example /etc/carbide/config.toml
vi /etc/carbide/config.toml   # tokens, db_dsn, api_addr (VPN interface!)
cp /path/to/carbide/packaging/carbide-server.service /etc/systemd/system/
cp /path/to/carbide/packaging/logrotate.carbide /etc/logrotate.d/carbide
systemctl daemon-reload && systemctl enable --now carbide-server

# 9. firewall: API port to sensors/VPN only, never the internet
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=10.8.0.0/24 port port=8440 protocol=tcp accept'
firewall-cmd --reload
```

## Install: sensor host

Needs: Python 3.11+ only (no Postgres/Podman/Squid). Small VM is fine.

```sh
pip install /path/to/carbide
useradd -r -s /usr/sbin/nologin carbide-sensor
mkdir -p /etc/carbide
cp /path/to/carbide/packaging/config-sensor.toml.example /etc/carbide/config.toml
vi /etc/carbide/config.toml   # sensor_id, token, server_host (VPN addr)
cp /path/to/carbide/packaging/carbide-sensor.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now carbide-sensor
# SSH host key self-generates at host_key_path on first start
```

## Verify it works

```sh
# sensor linked?
journalctl -u carbide-sensor -n 20 | grep linked
# -> "linked to carbide-server at ..."

# end-to-end login (use an allow-listed password from [auth])
ssh -p 2222 root@sensor-host
echo attacker-test > /tmp/x.txt; exit

# evidence landed? (on server host)
sudo -u postgres psql carbide -c \
  "SELECT session_id, attacker_ip, ended_at FROM sessions ORDER BY started_at DESC LIMIT 3;"
sudo -u postgres psql carbide -c \
  "SELECT substr(markdown, 1, 400) FROM reports ORDER BY at DESC LIMIT 1;"

# container + snapshot exist?
podman ps --filter label=carbide --format '{{.Names}} {{.Status}}'
podman images --filter reference='carbide-snap*' --format '{{.Repository}}:{{.Tag}}'

# egress path (from inside any affinity container):
podman exec <name> curl -sI http://example.com | head -3
sudo tail -2 /var/log/squid/access.log
```

## Configure

One file, strict validation: typos, wrong types, and bad values fail fast
at startup (exit 2). Defaults shown; only marked keys are required.

Sensor (`role = "sensor"`):

| Key | Default | Meaning |
|---|---|---|
| `sensor.listen_addr/listen_port` | `0.0.0.0` / `2222` | attacker-facing SSH socket |
| `sensor.host_key_path` * | — | ed25519 host key; generated if missing (back it up for stable fingerprint) |
| `sensor.server_host/server_port` * | — / `8440` | server API; use the VPN address |
| `sensor.sensor_id/token` * | — | identity; `token` must match `[server] tokens` entry |
| `sensor.spool_dir` * | — | durable outbox; growth = server unreachable, evidence safe |
| `sensor.request_timeout_s` | `10` | per API request timeout |
| `sensor.session_idle_timeout_s` | `600` | kill session after this long idle |
| `sensor.session_max_time_s` | `3600` | hard cap per session |
| `auth.passwords` | `[]` | always-accept list (known-bad researcher passwords) |
| `auth.accept_probability` | `0.0` | 0..1 roll per username per connection |
| `auth.max_attempts` | `10` | password tries before the connection is closed |

Server (`role = "server"`):

| Key | Default | Meaning |
|---|---|---|
| `server.api_addr/api_port` | `127.0.0.1` / `8440` | bind; set `api_addr` to the VPN interface |
| `server.tokens` * | — | `{ sensor-id = "token" }`, one per sensor |
| `server.db_dsn` * | — | Postgres DSN (local or over VPN) |
| `server.blob_dir` * | — | blob store; local disk or NFS mount |
| `podman.socket/image` | podman.sock / * | API socket; `image` must be built |
| `podman.port_range_start/end` | `22000`/`22100` | host ports for container sshd; needs ≥ max_containers + pool_size + 1 |
| `podman.network` | `""` | container network (created if missing); `""` = default |
| `podman.container_user` | `honey` | must match session user baked into the image |
| `podman.memory_mb/pids_limit` | `256`/`128` | per-container cgroup caps |
| `podman.pool_size` | `2` | pre-warmed fresh containers |
| `podman.ssh_host` | `""` | address sensors proxy to; `""` = api_addr |
| `affinity.keep_warm_minutes` | `10` | running idle grace, then stop (filesystem kept) |
| `affinity.max_containers` | `200` | LRU backstop |
| `affinity.idle_ttl_active_days` | `30` | evict active affinities after this long idle |
| `affinity.idle_ttl_inactive_hours` | `24` | evict never-active affinities after this |
| `affinity.snapshot_retention` | `10` | committed images kept per affinity |
| `affinity.commit_per_session` | `true` | snapshot on every session end (default on) |
| `forensics.max_file_bytes` | `1 MiB` | per-file content cap in reports |
| `forensics.include_full_export` | `false` | full `podman export` per session (eviction finals always try) |
| `squid.enabled/mode` | `true`/`transparent` | `transparent` needs nftables; `explicit` needs `explicit_proxy` |
| `squid.explicit_proxy` | `""` | e.g. `http://10.88.0.1:3128`; stamped into container sshd |
| `squid.log_path` | `/var/log/squid/access.log` | tailed for per-session hits |
| `quotas.blob_max_bytes` | `10 GiB` | blob store cap; over-quota files are pointer-only |
| `quotas.session_max_bytes` | `100 MiB` | per-session evidence cap; session flagged `over_quota` |
| `logging.level/dir` | `INFO`/`""` | `dir = ""` logs to stderr (journal); else rotating files |

Minimal sensor config:

```toml
role = "sensor"
[sensor]
host_key_path = "/etc/carbide/ssh_host_key"
server_host = "10.8.0.5"
sensor_id = "sensor-01"
token = "LONG-RANDOM-TOKEN"
spool_dir = "/var/lib/carbide/spool"
[auth]
passwords = ["password", "123456"]
accept_probability = 0.05
```

Generate tokens with `openssl rand -hex 24`.

## Operate

```sh
# services
systemctl status carbide-server carbide-sensor
journalctl -u carbide-server -f
journalctl -u carbide-sensor -f
tail -f /var/log/carbide/carbide-server.log   # if [logging] dir is set

# health: spool depth (0 = linked, growing = outage, evidence safe)
ls /var/lib/carbide/spool | wc -l

# health: recent sessions / reports / errors
sudo -u postgres psql carbide -c \
  "SELECT count(*), count(ended_at) FROM sessions WHERE started_at > now() - interval '1 hour';"
sudo -u postgres psql carbide -c "SELECT count(*) FROM reports;"
journalctl -u carbide-server --since '1 hour ago' -p warning | tail

# add a sensor: token on server + config on sensor, restart both
vi /etc/carbide/config.toml        # server: tokens = { ..., sensor-02 = "..." }
systemctl restart carbide-server carbide-sensor

# rotate a compromised sensor token (same two files, restart both)
openssl rand -hex 24

# read one session cold (see analyst-guide for the full flow)
sudo -u postgres psql carbide -c \
  "SELECT markdown FROM reports WHERE session_id = '...' \g /tmp/rep.md"

# walk an attacker's exact filesystem
podman run -it --rm <image-from-snapshots-table> /bin/sh

# affinity containers (running + stopped-but-kept)
podman ps -a --filter label=carbide --format '{{.Names}} {{.Status}}'

# stop a hot container now (keeps filesystem for forensics)
podman stop <container_id>

# find who owned a container IP (abuse reply)
sudo -u postgres psql carbide -c \
  "SELECT sensor_id, attacker_ip FROM affinities WHERE container_ip = '10.88.0.42';"

# disk pressure: blob store + postgres size
du -sh /var/lib/carbide/blobs
sudo -u postgres psql carbide -c "SELECT pg_size_pretty(pg_database_size('carbide'));"

# upgrade the honeypot image (rebuild, drop the diff baseline, restart)
podman build -t carbide-honeypot:latest /path/to/carbide/image/
podman rm -f carbide-ref   # stale diff baseline; recreated at next start
systemctl restart carbide-server
# existing affinities keep the old image until evicted; remove one early with
# podman rm -f <cid> after archiving its report (pool drops it on reconcile)
```

Back up: `pg_dump carbide`, the blob dir, sensor host keys, and both
`config.toml` files (tokens live there — treat as secrets).

## Troubleshoot

| Symptom | Check | Fix |
|---|---|---|
| sensor loops `server link down` | `journalctl -u carbide-sensor`; `ss -ltn` on server; VPN route | fix `server_host`/firewall; spool holds evidence meanwhile |
| `sensor rejected / bad credentials` | token mismatch | `sensor.token` must equal server `tokens[sensor_id]`; restart both |
| ssh connects but all logins fail | `[auth]` too strict | add passwords or raise `accept_probability` |
| sessions start, no container | `journalctl -u carbide-server`; `podman ps`; port range | widen `port_range_*`; check image exists; check pool errors |
| curl empty in container | `podman exec <c> env \| grep -i proxy`; `tail /var/log/squid/access.log` | explicit: check `explicit_proxy` + container ACL; transparent: check nftables |
| no squid hits for a session | `squid -k parse`; tailer errors in server log | fix `log_path`/ACL; Squid must log `carbide` format |
| `over_quota` on sessions | `[quotas]` too small for workload | raise caps or accept sampling |
| server won't start, exit 2 | stderr names the key | fix `/etc/carbide/config.toml` (strict validation) |
| disk filling | `du -sh` blob dir; `podman system df` | lower TTLs/retention/quotas; never blanket-`prune` (it deletes stopped affinities + snapshots) — remove specific containers after archiving |

Never expose `api_port` to the internet; never install `psycopg[binary]`
(system `libpq` only). Abuse handling: [abuse-runbook](abuse-runbook.md).
Analyst queries: [analyst-guide](analyst-guide.md). Wire protocol:
[protocol](protocol.md).
