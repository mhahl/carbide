# Carbide Ansible deployment

Installs `carbide-server` and `carbide-sensor` on Fedora hosts. Two roles,
three plays, no collection dependencies (`ansible.builtin` only).

## Layout

- `site.yml` — servers then sensors (whole fleet).
- `server.yml`, `sensor.yml` — one side only.
- `roles/carbide_server/` — packages, Postgres, Podman network + honeypot
  image, Squid, nftables egress rules (transparent mode), config, systemd,
  firewall, smoke check.
- `roles/carbide_sensor/` — packages, `carbide-sensor` user, SSH host key,
  config, systemd, firewall, smoke check.
- `inventory.example.ini` — copy to `inventory.ini` and edit.

## Prerequisites

- Control node: `ansible-core` 2.15+ (`dnf install ansible-core` or pip)
  plus GNU tar. The playbooks ship this checkout to targets, so run them
  from here.
- Targets: Fedora with SSH + a become-capable user (`-b -K` / NOPASSWD).
- Postgres/Squid/Podman are installed by the server role; sensors need only
  Python + SSH which the role installs.

## Quickstart

```sh
cd deploy
cp inventory.example.ini inventory.ini
vi inventory.ini            # hosts, api_addr, subnets, resolver
```

Secrets (tokens, DB password) go in vault, never in the inventory:

```sh
ansible-vault create group_vars/all/vault.yml   # or host_vars/<sensor>.yml
```

```yaml
carbide_db_password: "STRONG-DB-PW"
carbide_sensor_tokens: { sensor-01: "TOKEN-1", sensor-02: "TOKEN-2" }
```

Per-sensor tokens live in `host_vars/` (each sensor needs its own):

```yaml
# host_vars/sensor1.yml
carbide_sensor_token: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  ...
```

Then:

```sh
ansible-playbook -i inventory.ini site.yml --ask-vault-pass
# or one side:
ansible-playbook -i inventory.ini server.yml --ask-vault-pass
ansible-playbook -i inventory.ini sensor.yml --ask-vault-pass
```

## Single-host dev (server + sensor on one box)

Put the host in both groups and split the config paths (commented example at
the bottom of `inventory.example.ini`). Each role then installs a systemd
drop-in overriding `-c`, and the sensor link stays on `127.0.0.1` — no VPN.

```sh
ansible-playbook -i inventory.ini site.yml --ask-vault-pass
```

## Required variables

| Variable | Role | Meaning |
|---|---|---|
| `carbide_sensor_tokens` | server | `{ sensor-id = "token" }`, one per sensor |
| `carbide_db_password` | server | Postgres password for `carbide_db_user` |
| `carbide_nft_resolver` | server | site DNS resolver (transparent mode only) |
| `carbide_sensor_server_host` | sensor | server API address (VPN address when remote) |
| `carbide_sensor_id` | sensor | must match a key in `carbide_sensor_tokens` |
| `carbide_sensor_token` | sensor | must equal `tokens[id]` on the server |

## Key optional variables

| Variable | Default | Meaning |
|---|---|---|
| `carbide_api_addr` | `127.0.0.1` | server bind; set to the VPN interface when sensors are remote |
| `carbide_api_allow_subnets` | `[]` | firewalld sources allowed to the API port; `[]` adds no rule |
| `carbide_squid_mode` | `transparent` | or `explicit` (no nftables, containers get no DNS) |
| `carbide_container_subnet` / `_gateway` | `10.89.0.0/24` / `.1` | Podman network + Squid ACL + nft stay in sync via these |
| `carbide_nft_apply` | `true` | template + apply + persist egress rules at boot |
| `carbide_nft_hook_forward` | `true` | hook the drop chain into the forward path |
| `carbide_manage_firewall` | `true` | manage firewalld (API rules / sensor port) |
| `carbide_server_config_path` / `carbide_sensor_config_path` | `/etc/carbide/config.toml` | split these for single-host |
| `carbide_rebuild_image` / `carbide_force_reinstall` | `false` | force image build / pip reinstall on updates |

All role defaults (ports, TTLs, quotas, pool sizes) mirror the example
configs in `packaging/` — see `roles/*/defaults/main.yml`.

## Notes

- Re-runs are idempotent and are the update path: fresh source is shipped
  every run; set `carbide_force_reinstall=true` to reinstall the package
  when the version number hasn't changed, `carbide_rebuild_image=true` to
  rebuild the honeypot image.
- The server role creates the Postgres role/database if missing but never
  changes an existing role's password — rotate DB passwords manually.
- Postgres schema migrates itself at first server start.
- The API port (`8440`) and container ports (`22000–22100`) must never be
  reachable from the internet — only the sensor port (`2222`) is public.
- No SELinux module is shipped; the services run unconfined under the
  targeted policy. `pip` uses `--break-system-packages` on targets
  (override `carbide_pip_extra_args` if you vendor your own Python).
- Each play ends with a smoke check (`wait_for` on the API/SSH port) and a
  summary. Verify further per [admin-guide](../docs/admin-guide.md#verify-it-works).
