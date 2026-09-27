# Deployment

Two roles, one config file each (`/etc/carbide/config.toml`).

## Server host (beefy disk + CPU)

1. Install Postgres, Podman, Squid, Python 3.11+, and the system `libpq`
   (Fedora: `dnf install libpq`; the server needs the shared libpq at
   runtime — do NOT substitute the `psycopg[binary]` wheel, whose bundled
   OpenSSL corrupts the heap next to asyncssh); then install this package
   (`pip install .` or from your repo checkout).
2. Create the database and user:
   ```sql
   CREATE USER carbide WITH PASSWORD '...';
   CREATE DATABASE carbide OWNER carbide;
   ```
   Schema migrations run automatically at server start.
3. Build the honeypot image: `podman build -t carbide-honeypot:latest image/`
4. Create a dedicated container network (recommended):
   `podman network create carbide`, and set `[podman] network = "carbide"`.
5. Install `squid/squid.conf` (adjust the `containers` ACL to your network),
   generate the never-served dummy cert it references:
   `openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=carbide-splice -keyout /etc/squid/splice-dummy.pem -out /etc/squid/splice-dummy.pem`
   then `squid -k parse && systemctl enable --now squid`.
6. Transparent mode only: apply reviewed nftables rules from
   `squid/nftables.conf.snippet`. Explicit mode instead: set
   `[squid] mode = "explicit"` and `explicit_proxy` to the Squid address.
   The container entrypoint stamps the proxy into sshd (`SetEnv`), so
   attacker shells inherit it with no per-session setup.
7. Mount the NFS blob store at `[server] blob_dir` (or use local disk).
8. Copy `packaging/config-server.toml.example` to `/etc/carbide/config.toml`,
   set tokens + `db_dsn`, install `packaging/carbide-server.service`, and the
   logrotate file. `systemctl enable --now carbide-server`.
9. Open the API port **to sensors only** (VPN/firewall). The API is plain TCP
   with token auth — it must never face the internet.

## Sensor hosts (small, disposable)

1. Install Python 3.11+ and this package.
2. Copy `packaging/config-sensor.toml.example` to `/etc/carbide/config.toml`:
   unique `sensor_id`, the matching `token`, and the server address
   (VPN address or hostname).
3. Install `packaging/carbide-sensor.service`
   (`useradd -r -s /usr/sbin/nologin carbide-sensor` first),
   `systemctl enable --now carbide-sensor`.
4. The SSH host key generates on first start; back it up if you want a stable
   sensor fingerprint.

## Health signals

- Sensor logs `linked to carbide-server`; a growing `spool_dir` means the
  server/VPN is unreachable (evidence is safe, forwarding resumes).
- Server logs pool refills, forensics summaries, and evictions.
- Quotas: `[quotas]` caps the blob store and per-session evidence; Squid caps
  single bodies; logrotate bounds the logs. Size the blob filesystem and
  Postgres for your retention; eviction TTLs bound affinity containers.
