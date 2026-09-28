# Carbide administrator guide

Sensors take attacker SSH connections and forward evidence; one server runs
containers, Postgres, Squid, and forensics. Both roles run as podman compose
stacks from a single image (`quay.io/sigaint/carbide`).

```
attacker -> sensor:2222 (accept?) -> SSH proxy -> container:220xx (server host)
sensor --spool--> server:8440 (API) -> Postgres + blob store + reports
container -80/443-> Squid -> internet (logged, capped)
```

## Components: what and why

| Component | Where | What it does | Why it exists |
|---|---|---|---|
| `carbide-sensor` SSH front door | sensor stack | asyncssh server, auth policy, per-session proxy to containers | looks like a real server; cheap and disposable |
| auth policy | sensor | allow-listed passwords always in; else one probability roll per username per connection; `max_attempts` cap | D2: deterministic for known-bad, statistical for the rest |
| proxy bridge | sensor | pipes attacker channel to container sshd, records both directions | attacker interacts with a real system, not a script |
| transcript recorder | sensor | every byte in/out + `meta/command` records of exec requests | full session replay from Postgres |
| SCP carver | sensor | parses `scp -t/-f` streams into files, names by `scp` target | uploaded tools captured with destination paths |
| SFTP forwarder | sensor | proxies SFTP, carves up/downloads with full paths | same for SFTP |
| spool + server link | sensor | disk outbox, in-order forward, ack removes; reconnects with backoff | evidence survives VPN/server outages; server dedupes replays |
| server API | server stack | token-auth JSON-lines TCP: `container_for` + idempotent records | single choke point; treats sensors as untrusted |
| affinity pool | server | one container per (sensor, attacker IP); reuse on reconnect; pre-warmed fresh pool | attacker persistence across sessions; fast handoff |
| forensics | server | on session end: container diff vs `carbide-ref`, file contents, unified diffs, report, snapshot commit | easy per-session "what changed" without manual diffing |
| eviction | server | stops idle-warm containers; TTLs (active 30d / inactive 24h) + 200-container LRU backstop; final archive first | bounds disk/CPU/abuse window automatically |
| Squid tailer | server | tails `access.log`, attributes hits to sessions by container IP | egress visibility without TLS interception |
| Postgres | server stack (`db`) | sessions, auth, transcripts, files, diffs, reports, snapshots, squid hits, affinities | metadata + pointers; blobs live in a volume |
| blob store | server named volume | `<blob_dir>/<2-hex>/<sha256>`, content-addressed, quota-capped | identical payloads stored once across fleet |
| honeypot image | server host (siblings) | Alpine + sshd + `honey` user; entrypoint sets password, stamps proxy `SetEnv` | real Linux target; unique host keys per container |
| Squid | server stack (`squid`) | explicit :3128, peek-and-splice TLS (SNI logged, never decrypted) | web egress with logging, ACLs, body caps |

Honeypot containers are siblings on the host (the server reaches the host
podman socket), on the shared `carbide` network — never nested inside the
server container.

## Install: server host

Needs: Fedora/RHEL-like with root, and a VPN/tailnet address sensors use.

```sh
# 1. prerequisites + the stack files
dnf install -y podman podman-compose openssl gettext-envsubst firewalld
git clone <carbide-repo> && cd carbide/compose/server
# (or: scp -r compose/server/ root@server-host:/root/carbide-server/)

# 2. run setup (creates network, pulls images, generates secrets,
#    renders config.toml, firewalls the API, starts the stack)
./setup.sh --ssh-host 10.8.0.5 --api-bind 10.8.0.5 \
  --allow-subnet 10.8.0.0/24
# -> prints SENSOR_TOKEN: copy it, every sensor needs it
```

What setup did: created the `carbide` podman network (fixed `10.89.0.0/24`
subnet the Squid ACL expects), pulled `carbide`, `carbide-squid`,
`carbide-honeypot`, and `postgres:16` images, generated hex `SENSOR_TOKEN` +
`DB_PASSWORD` into `.env` (never overwritten on re-runs), rendered
`config.toml` from the template, added firewalld rich rules for your
subnets, and started `server` + `db` + `squid`. Postgres migrates itself at
first server start.

## Install: sensor host

Needs: podman, podman-compose, envsubst. Small VM is fine; root only for
the firewall step.

```sh
dnf install -y podman podman-compose gettext-envsubst firewalld
# copy compose/sensor/ to the host, then:
./setup.sh --server-host 10.8.0.5 --sensor-id sensor-01 \
  --token <SENSOR_TOKEN-from-server>
# SSH host key self-generates into a persisted volume on first start
```

## Verify it works

From `compose/server/` on the server host (and any host for the ssh step):

```sh
# stack healthy?
podman compose ps
podman compose logs sensor 2>/dev/null; podman compose logs server | tail -5

# sensor linked? (on the sensor host)
podman compose logs sensor | grep linked
# -> "linked to carbide-server at ..."

# end-to-end login (use an allow-listed password from the sensor .env)
ssh -p 2222 root@sensor-host
echo attacker-test > /tmp/x.txt; exit

# evidence landed?
podman compose exec db psql -U carbide carbide -c \
  "SELECT session_id, attacker_ip, ended_at FROM sessions ORDER BY started_at DESC LIMIT 3;"
podman compose exec db psql -U carbide carbide -c \
  "SELECT substr(markdown, 1, 400) FROM reports ORDER BY at DESC LIMIT 1;"

# sibling containers + snapshots exist? (on the server HOST, not in compose)
podman ps --filter label=carbide --format '{{.Names}} {{.Status}}'
podman images --filter reference='carbide-snap*' --format '{{.Repository}}:{{.Tag}}'

# egress path (from inside any affinity container):
podman exec <name> curl -sI http://example.com | head -3
podman compose exec squid tail -2 /var/log/squid/access.log
```

## Configure

Each stack keeps a small `.env` (setup renders `config.toml` from
`config.toml.tmpl`). Re-run `./setup.sh` after editing `.env` to re-render
and restart. Secrets are hex so no quoting issues; never commit `.env`.

Server `.env`:

| Key | Default | Meaning |
|---|---|---|
| `TAG` | `latest` | image tag for all three carbide images |
| `API_BIND` / `API_PORT` | `10.89.0.1` / `8440` | host bind for the server API: the container-only carbide gateway by default; set `API_BIND` to the VPN interface when sensors are remote |
| `SSH_HOST` | `10.89.0.1` | address sensors use for container sshd: the gateway when co-located, the VPN IP of this host when remote |
| `SENSOR_TOKEN` * | generated | the one token shared by all sensors |
| `DB_PASSWORD` * | generated | Postgres password (also fed to the `db` service) |

Sensor `.env`:

| Key | Default | Meaning |
|---|---|---|
| `TAG` | `latest` | image tag |
| `SERVER_HOST` / `SERVER_PORT` * | — / `8440` | server API; VPN address when remote, the carbide gateway (`10.89.0.1`) when co-located |
| `SENSOR_ID` * | — | unique per sensor (namespaces affinity); must differ on every sensor |
| `SENSOR_TOKEN` * | — | must equal the server's `SENSOR_TOKEN` |
| `LISTEN_ADDR` / `LISTEN_PORT` | `0.0.0.0` / `2222` | attacker-facing SSH socket |
| `AUTH_PASSWORDS` | `"password", "123456", ...` | TOML fragment: always-accept list |
| `ACCEPT_PROBABILITY` | `0.05` | 0..1 roll per username per connection |

Need a knob that isn't in `.env` (TTLs, quotas, pool)? Edit
`config.toml.tmpl`, re-run `setup.sh`. Every key is validated with explicit
errors on typos, missing values, and out-of-range numbers; the service
fails fast (exit 2) naming the key. Full key reference:
`packaging/*.example`.

## Operate

All server commands from `compose/server/`, sensor commands from
`compose/sensor/`:

```sh
# status + logs
podman compose ps
podman compose logs -f server
podman compose logs -f sensor

# health: spool depth (empty = linked, growing = outage, evidence safe)
podman compose exec sensor ls /var/lib/carbide/spool | wc -l

# health: recent sessions / reports / errors
podman compose exec db psql -U carbide carbide -c \
  "SELECT count(*), count(ended_at) FROM sessions WHERE started_at > now() - interval '1 hour';"
podman compose logs server --since 1h | grep -i warn | tail

# add a sensor: same shared token, new unique id, on the new box
./setup.sh --server-host <vpn-ip> --sensor-id sensor-02 --token <SENSOR_TOKEN>

# rotate the shared token (server + EVERY sensor, then restart all)
vi .env                       # server: set a fresh SENSOR_TOKEN
./setup.sh --skip-firewall    # re-renders + restarts
# on each sensor: set the same token in .env, re-run ./setup.sh

# upgrade images (build first: images/build-push.sh <tag>)
vi .env                       # set TAG=<tag>
./setup.sh --skip-firewall    # pulls + recreates

# read one session cold (see analyst-guide for the full flow)
podman compose exec db psql -U carbide carbide -c \
  "SELECT markdown FROM reports WHERE session_id = '...'"

# walk an attacker's exact filesystem (server host)
podman run -it --rm <image-from-snapshots-table> /bin/sh

# affinity containers (running + stopped-but-kept, server host)
podman ps -a --filter label=carbide --format '{{.Names}} {{.Status}}'

# stop a hot container now (keeps filesystem for forensics)
podman stop <container_id>

# find who owned a container IP (abuse reply)
podman compose exec db psql -U carbide carbide -c \
  "SELECT sensor_id, attacker_ip FROM affinities WHERE container_ip = '10.89.0.42';"

# disk pressure: named volumes + postgres size
podman system df -v | grep -A3 carbide
podman compose exec db psql -U carbide carbide -c \
  "SELECT pg_size_pretty(pg_database_size('carbide'));"

# upgrade the honeypot image (rebuild + push, drop the diff baseline)
images/build-push.sh <tag>    # from the repo
podman pull quay.io/sigaint/carbide-honeypot:<tag>
podman rm -f carbide-ref      # stale baseline; recreated at next start
vi .env && ./setup.sh         # set TAG, restart
```

Back up: `podman compose exec db pg_dump -U carbide carbide`, the
`carbide-blobs` volume, the sensor `sensor-keys` volume, and both `.env`
files (tokens live there — treat as secrets).

## Troubleshoot

| Symptom | Check | Fix |
|---|---|---|
| sensor loops `server link down` | `compose logs sensor`; API bind/port; VPN route | fix `SERVER_HOST`/firewall; spool holds evidence meanwhile |
| `sensor rejected / bad credentials` | token mismatch | sensor `SENSOR_TOKEN` must equal the server's; re-run both setups |
| ssh connects but all logins fail | auth too strict | extend `AUTH_PASSWORDS` or raise `ACCEPT_PROBABILITY` |
| sessions start, no container | `compose logs server`; `podman ps`; socket mount | server stack must run rootful with `/run/podman/podman.sock` mounted (setup does this) |
| sensor can't reach container sshd | `SSH_HOST` on server | remote sensors: VPN IP of the server host; co-located: the carbide gateway (`10.89.0.1`) |
| curl empty in container | `podman exec <c> env \| grep -i proxy`; squid logs | explicit proxy is stamped at container creation; `podman compose logs squid` |
| no squid hits for a session | `compose logs squid`; `log_path` volume | squid-logs volume must be shared with `server` (compose does this) |
| `over_quota` on sessions | quotas too small for workload | raise caps in the template or accept sampling |
| server won't start, exit 2 | `compose logs server` names the key | fix `.env`/template (strict validation), re-run setup |
| `db` never healthy | `compose logs db`; disk | check volume space; password changes need a fresh volume (Postgres only reads `POSTGRES_PASSWORD` on first init) |
| link fails after interrupted compose ops | `nft list ruleset \| grep <port>` shows stale DNAT | `podman compose down`, `podman network rm carbide`, re-run `setup.sh` (it recreates the network) |
| disk filling | `podman system df -v`; `podman images` | lower TTLs/retention/quotas; never blanket-`prune` (it deletes stopped affinities + snapshots) — remove specific containers after archiving |

Never expose the API port to the internet. Abuse handling:
[abuse-runbook](abuse-runbook.md). Analyst queries:
[analyst-guide](analyst-guide.md). Wire protocol: [protocol](protocol.md).
