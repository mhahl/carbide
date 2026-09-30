# Carbide — Settled Decisions

**Status: Final** — accepted by the user (see Acceptance).
**Subject:** the carbide SSH honeypot plan (Python, single `/etc/carbide/config.toml`, Podman API pool, IP-affinity containers, per-session recording, forensic diffs).

## Goal

Run an SSH honeypot fleet: lightweight sensors mimic an SSH server, accept
connections per a password policy, and proxy accepted sessions to containers on
a central server — each new source IP gets a fresh container and each returning
IP gets its previous container back (per sensor). Sensors record all input and
copied files per session and ship evidence store-and-forward to the server,
which keeps postgres metadata plus an NFS blob store and produces
easy-to-examine forensic diffs of container changes.

## Non-goals (confirmed)

- No hand-rolled SSH protocol code; no container management outside the Podman API.
- No custom filesystem work: forensic diffs come from Podman's container-changes API.
- No full-TLS-MITM proxy (discussed, rejected in D3).
- No production operation of the honeypot; delivery ends at tested, packaged,
  documented code (see Scope contract).

## Constraints (user-stated, settled)

- Python implementation; all configuration in `/etc/carbide/config.toml`.
- Containers managed through the Podman API (podman-py).
- New IP → new container from a pool; same IP reconnecting → its previous container.
- Containers are not deleted on disconnect.
- All session input and copied files saved per session.

## Decisions

- **D1 — Record location:** this file, `DECISIONS.md` at the repo root, held as
  Draft until explicitly accepted. (Settled: user chose "recommended".)
- **D2 — Auth probability semantics:** allow-listed passwords always accept. For any
  other password, carbide rolls once per username per connection on the first
  attempt with that username; the outcome sticks for that username for the rest of
  the connection, and each different username gets its own roll. Failed-roll
  usernames keep failing (still logged) until reconnect. (Settled: user chose
  "single roll, per username".)
- **D3 — Egress: transparent Squid without MITM, in this stage's scope.**
  Peek-and-splice SNI logging, full HTTP request/response logging, containers
  with no direct DNS (the proxy resolves, killing container-originated DNS
  tunneling), cloud-metadata/link-local blocks, CONNECT port restrictions, byte
  quotas, and per-session log attribution by container IP. Full MITM was
  discussed and rejected: CA lifecycle, certificate-forgery fingerprint, and
  decrypted-content retention Gordon judged too costly. (Settled: user chose
  "recommended".)
- **D4 — Forensic capture: snapshots default on.** Every session end records the
  cumulative diff plus changed-file contents (the easy-to-examine report) AND
  commits the container to a per-affinity image snapshot. Snapshot history is
  bounded by a per-container retention cap (config knob, exact default ships in
  the example config). Rationale: exact restorable history at any point; storage
  is bounded by the cap plus affinity eviction. (Settled: user chose "snapshots
  default on".)
- **D5 — Idle containers: keep-warm window.** When an IP's last session ends, its
  container keeps running for a configurable N minutes (exact default ships in
  the example config), then is stopped; filesystem state is preserved either
  way. Rationale: fast reconnects and brief process continuity, with bounded
  unattended execution. (Settled: user chose "keep warm for N minutes".)
- **D6 — Eviction: tiered idle TTL plus LRU backstop.** Containers with no
  recorded session activity are reaped after a short TTL (default 24h);
  containers with activity keep a long TTL (default 30 days); a max-containers
  LRU backstop (default 200) covers floods. A final forensic archive is always
  written before any removal. All three numbers are config knobs. Rationale:
  scanner junk expires fast without evicting interesting attackers early.
  (Settled: user chose "recommended".)
- **D7 — Stage boundary: wide, revised for the D8 split.** In scope:
  carbide-sensor (SSH front door, D2 auth, session proxy/recording, local
  spool), carbide-server (server API, per-sensor affinity pools, forensics
  pipeline, eviction job, postgres schema plus migrations, D10 NFS blob store),
  the sensor↔server protocol, the honeypot image definition, the D3 Squid
  integration with per-session attribution, two-role service packaging with
  example configs (each role keeps the single-file rule: one config.toml per
  host, role-appropriate keys), README plus analyst docs plus abuse-handling
  runbook, unit plus live integration tests, and operational hardening
  (quotas, rotation, runbook). Out of scope: full-TLS-MITM, the VPN/private
  network itself, production operation, the S3 blob backend (deferred behind
  the D10 interface), and any second stage. (Settled: "wide", revised for
  D8–D10.)
- **D8 — Sensor/server split adopted.** carbide-sensor runs the SSH front door,
  session proxy/recording, and a local spool queue; it talks only to a
  carbide-server API and never touches Podman or postgres directly.
  carbide-server owns Podman (local socket), Squid, postgres, the forensics
  pipeline, and eviction. Sensors ship evidence store-and-forward so VPN/DB
  blips lose nothing; the VPN itself is out of carbide's scope (carbide just
  sees addresses). Rejected: sensors writing postgres directly (DB credentials
  on every exposed sensor, log-poisoning risk, no clean orchestration point).
  (Settled: user chose "recommended".)
- **D9 — Affinity is per-sensor.** Each sensor has its own IP→container
  namespace; the same attacker IP on two sensors gets two unrelated containers.
  Rationale: sensors stay unlinkable (no shared state leaks the fleet),
  mapping stays a simple per-sensor table, and container problems stay local to
  one sensor's view. Rejected: global affinity (observably links sensors,
  needs cross-sensor shared-container handling). (Settled: user chose
  "recommended".)
- **D10 — Blobs on NFS-served filesystem, pointers in postgres.** Carbide-server
  writes evidence blobs (session files, changed-file contents, export tarballs,
  captures) to a plain directory path served by the deployment's NFS — local
  disk behaves identically, carbide only ever sees a path — named by content
  hash for dedupe and integrity; postgres holds metadata, transcripts, indexes,
  and hash-plus-path pointers. Blob access stays behind a narrow put/get/delete
  interface so an S3-compatible backend can replace the filesystem later.
  Rejected: S3 now (a whole storage system inside this stage), all-bytea
  (database bloat, slow large reads). (Settled: user chose "recommended with
  nfs".)

## Open questions (the interview tree — visibly unresolved)

- O1: Auth probability semantics — SETTLED as D2.
- O2: Container egress policy — SETTLED as D3.
- O3: Forensic granularity default — SETTLED as D4.
- O4: Idle-container handling and eviction — SETTLED as D5 and D6.
- O5: Deliverable boundary and done-means checklist — SETTLED as D7.
- O6: Sensor/server split proposal — SETTLED as D8.
- O7: Affinity scope across sensors — SETTLED as D9.
- O8: Evidence blob storage — SETTLED as D10.
- D7 and the scope contract revised for D8–D10; re-acceptance requested below.

## Risks (confirmed)

- SSH-proxy fidelity (PTY, resize, signals, SFTP quirks could fingerprint the honeypot).
- podman-py is synchronous; all calls must run off the asyncio event loop.
- Persistent per-IP containers increase escape/abuse exposure over time.
- NAT sharing: all clients behind one public IP share a container.
- Exit-traffic abuse (blocklisting, provider complaints) from the D3 egress path;
  mitigated by quotas, CONNECT/port restrictions, and the abuse-handling runbook.
- Disk exhaustion from snapshots, payloads, and logs; mitigated by enforced quotas.
- Sensor credentials: API tokens live on exposed sensors; the server must treat
  all sensor input as untrusted and scope tokens per sensor.
- Central postgres as a single point of failure; mitigated by sensor spooling,
  with DB backup/HA explicitly out of this stage.

## Validation (confirmed)

- Unit tests (both roles: config, D2 auth distribution with seeded RNG, affinity
  map, spool queue, eviction order, diff normalization, report rendering) plus a
  live two-sensor end-to-end against one server with the stock `ssh`/`sftp`/`scp`
  clients, including a forced server-outage spool-recovery check and quota and
  rotation behavior under a forced-fill check.

## Scope contract (accepted)

### Artifact boundary

In scope: the carbide-sensor and carbide-server packages, the sensor↔server
protocol, the postgres schema plus migrations, the D10 blob-store layout and
interface, the honeypot image definition, the D3 Squid integration with
per-session attribution, two-role service packaging with example configs (one
config.toml per host), README plus analyst docs plus abuse-handling runbook,
unit and live integration tests, and this decision record.
Out of scope: full-TLS-MITM proxy, the VPN/private network itself, production
operation, the S3 blob backend, follow-on hardening beyond
quotas/rotation/runbook, and any second stage (none currently planned).

### Done means

- [ ] Unit suite passes (both roles).
- [ ] Live two-sensor end-to-end against one server passes: D2 accept semantics,
      same-IP reconnect resumes its container, new IP gets a fresh one, the
      second sensor proves per-sensor affinity (same IP, unrelated containers),
      Squid logs land in the right session, eviction archives before removing.
- [ ] Sensor spooling verified: evidence survives a forced server outage and
      forwards on recovery with nothing lost or duplicated.
- [ ] Blob pointer↔file integrity check passes (hashes verify).
- [ ] One session reads cold from its database row plus blobs, without other tools.
- [ ] Disk quotas and log rotation verified live.
- [ ] This record accepted as Final.

### Execution rule

"Go", "do it all", and similar words authorize only the boundary above. Work
that would add an artifact class, a new program of tasks, or anything outside
this boundary stops first: it needs your explicit approval of the wider
boundary, or it moves to a follow-up with its own interview. Never build first
and ask afterwards.

## Acceptance

ACCEPTED — the user approved the scope contract above and this record as Final.
Quoted acceptance: "accept" (channel: this chat session,
time: 2026-09-27T08:40:57Z). There is no owning issue in this workspace, so
this section is the coordination record.

## Web console extension (Final)

**Status: Final** — accepted by the user (see Acceptance below).
Everything above remains Final as accepted. It extends the D7 boundary
with an analyst and administrator web console built into carbide-server
(htmx + Alpine.js + DaisyUI, per the feature request).

Settled constraints (user-stated in the feature request):
- W0a — Frontend stack is htmx + Alpine.js + DaisyUI, wireframe theme,
  side navigation.
- W0b — Console auth is database-backed username + password; every
  console user has full administration permission (no roles).
- W0c — Console shows realtime logs, sessions, and container state, and
  supports interacting with sessions in real time.
- W0d — Console administers sensors: list/state, push password
  allow-list + accept probability, restart over SSH via a service
  account, and configure new sensors.

Open questions: none — all settled (Q1–Q5 answered, Q6 accepted below).

Decisions (written as they settle):
- W1 — Session interaction is kill + controls (user chose option 1,
  2026-09-28): the console can terminate a live attacker session, stop /
  start / restart its container, evict the affinity, and tail the live
  transcript and container state. No terminal emulation in the browser.
  Rationale: covers realtime interaction with one small server→sensor
  message on the existing link; a browser terminal would be a separate
  project's scope and attack surface.
- W2 — New-sensor provisioning is full remote install (user chose
  option 1, 2026-09-28): the console registers the sensor, SFTPs the
  `compose/sensor/` files, writes the remote `.env`, runs `setup.sh`
  over SSH as the service account, and shows the output. Precondition:
  the target host already has podman, podman-compose, and envsubst;
  remote firewall stays out-of-band (non-root service account).
- W3 — Sensitive credentials are visible in analyst views (user chose
  option 1, 2026-09-28): auth-attempt passwords and affinity container
  SSH credentials render inline. Rationale: this is investigation data
  the console exists to expose, and with every console user a full admin
  (W0b) masking would be theater — the pages read straight from the
  database.
- W4 — Admin-action audit is server log lines only (user chose
  option 1, 2026-09-28): every console mutation logs who did what to
  which target at INFO. No DB audit table. Rationale: greppable,
  rotated, zero new schema; nothing in the request needs queryable
  audit history on this VPN-only admin tool.
- W5 — Default web bind follows the sensor API pattern (user chose
  option 2, 2026-09-28): reachable from the VPN/sensor networks out of
  the box via setup flags, with firewall rules mirroring the API's
  `--allow-subnet` pattern. Rationale: consistent with how the API is
  already exposed; the operator narrows it the same way.

Scope contract (accepted): deliverable is the console inside
carbide-server — `src/carbide/server/web/` plus templates/static, DB
migration 2 (`web_users`, `web_sessions`, `managed_sensors`),
`[web]`/`[sensor_mgmt]` config, server→sensor notify plus the sensor
kill handler, the asyncssh management layer, setup/compose/docs
updates, and tests — published as one commit per phase (foundation,
read-only views, actions, realtime interaction, provisioning and
packaging). Out of scope: terminal emulation, roles/RBAC, a DB audit
table, CSRF tokens v1, login rate-limiting, metrics/alerting, mobile,
sensor-side UI (each a follow-up with its own interview if ever
wanted). Done means: (1) all five phase commits landed; (2) full unit
suite green; (3) container builds with the new deps; (4) manual E2E
evidence — login, cold session read, diff compare, live kill, sensor
config push + restart, clean teardown; (5) admin + analyst docs
updated. "Go" and similar words authorize only this boundary.

Acceptance: "accept and build" (channel: this chat session, time:
2026-09-29T00:03:38Z). The "build" half is the separate explicit
implementation request: build the accepted boundary now. There is no
owning issue in this workspace, so this section is the coordination
record.

## Threat intel extension (Final)

**Status: Final** — accepted by the user (see Acceptance below).
Everything above remains Final as accepted. It extends the boundary with
VirusTotal file verdicts for session evidence blobs (hash cache in
Postgres, linked to files), automatic nmap profiling of attacking IPs,
and a per-IP attacker view in the console.

Settled constraints (user-stated in the feature request):
- T0a — Files copied or downloaded through the proxy are uploaded to
  VirusTotal, scanned, and results stored in the database.
- T0b — Carbide links downloaded files to their scan results.
- T0c — Carbide stores scan results to minimize VirusTotal load.
- T0d — Carbide automatically scans the attacking IP with nmap and shows
  it in an attacker view with information about that IP.

Open questions (the interview tree — visibly unresolved):
- Q1: Download bytes — SETTLED as T1.
- Q2: VirusTotal tier — SETTLED as T2.
- Q3: nmap default — SETTLED as T3.
- Q4: nmap profile — SETTLED as T4.
- Q5: Backfill — SETTLED as T5.
- Q6: Scope contract and acceptance — SETTLED (accepted below).

Decisions (written as they settle):
- T1 — Session blobs only; no proxy-download bytes in this stage (user
  chose option 3, 2026-09-30): VirusTotal-scan only files carbide already
  holds as evidence (session uploads, forensic contents). No URL refetch,
  no squid body capture — so proxy downloads get no verdicts for now, and
  T0a/T0b apply to copied/session files only. Rationale: smallest correct
  scope; download-byte capture returns as its own follow-up interview if
  ever wanted.
- T2 — Public VirusTotal key (user chose option 1, 2026-09-30): free
  Community tier, 4 requests/minute and 500/day, non-commercial use only.
  The worker paces itself to these limits with a persisted daily counter;
  rate numbers stay config knobs so a premium key works later without code
  changes.
- T3 — nmap runs automatically for every new attacking IP (user chose
  option 1, 2026-09-30): first sighting queues one scan, result cached 7
  days; a config flag disables it. Rationale: T0d as stated, hands-free
  intel; unsolicited-traffic concern contained by the connect-scan profile
  (T4) and the disable flag.
- T4 — nmap profile is connect scan plus version detection (user chose
  option 3, 2026-09-30): `-sT -sV --top-ports 1000`, unprivileged, one
  scan per IP per 7 days, serialized with a timeout. Rationale: richest
  useful intel (what is actually listening, not just what is open);
  accepted cost is slower, chattier scans. Profile stays a config knob.
- T5 — New files only, plus a manual backfill command (user chose option
  1, 2026-09-30): the worker scans evidence captured after deploy; a
  `carbide-server --vt-backfill` flag drains pre-existing blobs on demand.
  Rationale: steady-state quota stays predictable at 500/day; history
  spend is the operator's explicit choice.

Scope contract (accepted): deliverable is VT verdicts
for session evidence blobs inside carbide-server — `server/vt.py` client
(hash lookup, upload-if-unknown ≤32MB, analysis polling, 4/min + 500/day
pacing with persisted counter, 429/5xx backoff) plus queue worker,
`--vt-backfill` command, `server/ipintel.py` nmap worker (`-sT -sV`,
one scan per IP per 7 days, disable flag), DB migration 3 (`vt_scans`,
`ip_intel`), `[virustotal]`/`[ipintel]` config, nmap in the server
image, `/attackers` + `/attackers/{ip}` console views with verdict
badges, setup/compose/docs updates, and tests. Out of scope:
proxy-download bytes (refetch/ICAP — follow-up with its own interview),
premium-tier behavior beyond config knobs, SYN/raw scans, blocking
traffic on verdicts, downloading samples from VT, and everything
already out of scope above. Done means: (1) migration 3 applies cleanly;
(2) a captured file shows its verdict on its session page; (3) a new
attacker IP gets an nmap profile on its attacker page within the scan
timeout; (4) full unit suite green; (5) admin + analyst docs updated.
"Go" and similar words authorize only this boundary.

Acceptance: "accept" (channel: this chat session, time:
2026-09-30T00:22:09Z). There is no owning issue in this workspace, so
this section is the coordination record.
