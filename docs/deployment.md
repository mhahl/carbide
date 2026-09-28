# Deployment

Both roles ship as containers from one image (`quay.io/sigaint/carbide`)
and run under podman compose. Full operator detail lives in
[admin-guide](admin-guide.md); this is the checklist.

## Server host (beefy disk + CPU)

Prereqs: podman, podman-compose, openssl, envsubst (`gettext-envsubst`),
root for the podman socket and firewall.

1. Copy `compose/server/` to the host (or clone the repo).
2. Run setup (as root):
   ```sh
   ./setup.sh --ssh-host <vpn-ip-of-this-host> --api-bind <vpn-ip> \
     --allow-subnet <sensor-net-cidr>
   ```
   This creates the shared `carbide` network, pulls images, generates the
   sensor token + DB password into `.env`, renders `config.toml`, restricts
   the API port to your subnets, and starts the stack (server + Postgres +
   Squid). Schema migrations run automatically at first server start.
3. Copy the printed `SENSOR_TOKEN` — every sensor needs it.
4. The API is plain TCP with token auth: VPN-only plus firewall, never the
   internet. Container sshd ports (`22000–22100`) stay host-internal too.

## Sensor hosts (small, disposable)

Prereqs: podman, podman-compose, envsubst. Root only for the firewall step.

1. Copy `compose/sensor/` to the host.
2. Run setup:
   ```sh
   ./setup.sh --server-host <vpn-ip-of-server> --sensor-id <unique-id> \
     --token <SENSOR_TOKEN>
   ```
   Unique `sensor_id` per sensor (it namespaces affinity); the token is the
   one shared value from the server.
3. The SSH host key self-generates into a persisted volume on first start.

## Health signals

- Sensor logs `linked to carbide-server` (`podman compose logs sensor`); a
  growing spool (`podman compose exec sensor ls /var/lib/carbide/spool`)
  means the server/VPN is unreachable (evidence is safe, resumes on link).
- Server logs pool refills, forensics summaries, and evictions
  (`podman compose logs server`).
- Quotas: `[quotas]` caps the blob store and per-session evidence; Squid caps
  single bodies. Size host disk for the named volumes; eviction TTLs bound
  affinity containers.
