#!/usr/bin/env bash
# Carbide server setup: pull images, generate secrets, render config,
# open the firewall, start the compose stack. Idempotent — re-run to
# upgrade (after bumping TAG in .env) or to repair. Must run as root
# (rootful podman socket + firewall).
#
# Usage: ./setup.sh [--allow-subnet CIDR]... [--api-bind IP] [--ssh-host HOST]
#          [--tag TAG] [--nfs-export HOST:/PATH] [--nfs-mountpoint PATH]
#          [--web-bind IP] [--web-port PORT] [--mgmt-key PATH]
#          [--skip-firewall] [--skip-pull]
set -euo pipefail

cd "$(dirname "$0")"

ALLOW_SUBNETS=()
# Flag values live in F_* so they can't be confused with load_env values
# below: only explicit flags append to .env, never re-runs.
F_API_BIND=""; F_SSH_HOST=""; F_TAG=""; F_NFS_EXPORT=""; F_NFS_MOUNTPOINT=""
F_WEB_BIND=""; F_WEB_PORT=""; F_MGMT_KEY=""
SKIP_FIREWALL=0; SKIP_PULL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --allow-subnet) ALLOW_SUBNETS+=("$2"); shift 2 ;;
    --api-bind) F_API_BIND="$2"; shift 2 ;;
    --ssh-host) F_SSH_HOST="$2"; shift 2 ;;
    --tag) F_TAG="$2"; shift 2 ;;
    --nfs-export) F_NFS_EXPORT="$2"; shift 2 ;;
    --nfs-mountpoint) F_NFS_MOUNTPOINT="$2"; shift 2 ;;
    --web-bind) F_WEB_BIND="$2"; shift 2 ;;
    --web-port) F_WEB_PORT="$2"; shift 2 ;;
    --mgmt-key) F_MGMT_KEY="$2"; shift 2 ;;
    --skip-firewall) SKIP_FIREWALL=1; shift ;;
    --skip-pull) SKIP_PULL=1; shift ;;
    *) echo "usage: $0 [--allow-subnet CIDR]... [--api-bind IP] [--ssh-host HOST] [--tag TAG] [--nfs-export HOST:/PATH] [--nfs-mountpoint PATH] [--web-bind IP] [--web-port PORT] [--mgmt-key PATH] [--skip-firewall] [--skip-pull]" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "error: run as root (podman socket + firewall)" >&2
  exit 1
fi
for cmd in podman openssl envsubst; do
  command -v "$cmd" >/dev/null || {
    echo "error: missing $cmd" >&2; exit 1; }
done
if podman compose version >/dev/null 2>&1; then
  COMPOSE="podman compose"
elif command -v podman-compose >/dev/null; then
  COMPOSE="podman-compose"
else
  echo "error: no compose provider (dnf install podman-compose)" >&2
  exit 1
fi

# 0. host podman API socket (the server drives sibling containers through it)
SOCK=/run/podman/podman.sock
if [ -e "$SOCK" ] && [ ! -S "$SOCK" ]; then
  # A previous `compose up` while the socket was down auto-created this
  # path as a directory; systemd cannot bind over it, and any container
  # created against it wedges with crun "Not a directory".
  if [ -d "$SOCK" ] && rmdir "$SOCK" 2>/dev/null; then
    echo "removed stale directory shadowing $SOCK" >&2
  else
    echo "error: $SOCK exists but is not a socket; remove it, then re-run" >&2
    exit 1
  fi
fi
if [ ! -S "$SOCK" ]; then
  systemctl enable --now podman.socket >/dev/null 2>&1 || {
    echo "error: cannot start podman.socket" >&2; exit 1; }
fi
[ -S "$SOCK" ] || {
  echo "error: $SOCK still missing" >&2; exit 1; }

# 1. shared network for stack + honeypot siblings (subnet fixed: squid ACL)
if ! podman network exists carbide >/dev/null 2>&1; then
  podman network create --subnet 10.89.0.0/24 --gateway 10.89.0.1 carbide
fi

# 2. config + secrets (generated once, never overwritten)
[ -f .env ] || cp .env.example .env
chmod 600 .env

load_env() {  # literal KEY=value lines (last value per key wins).
  # Values containing spaces must be single-quoted for compose's dotenv
  # parser; one layer of surrounding single quotes is stripped here.
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|\#*) continue ;; esac
    key="${line%%=*}"; value="${line#*=}"
    case "$key" in *[!A-Za-z0-9_]*|"") continue ;; esac
    if [ "${value#\'}" != "$value" ] && [ "${value%\'}" != "$value" ]; then
      value="${value#\'}"; value="${value%\'}"
    fi
    export "$key=$value"
  done < .env
}
load_env
[ -n "$F_API_BIND" ] && echo "API_BIND=$F_API_BIND" >> .env
[ -n "$F_SSH_HOST" ] && echo "SSH_HOST=$F_SSH_HOST" >> .env
[ -n "$F_TAG" ] && echo "TAG=$F_TAG" >> .env
[ -n "$F_WEB_BIND" ] && echo "WEB_BIND=$F_WEB_BIND" >> .env
[ -n "$F_WEB_PORT" ] && echo "WEB_PORT=$F_WEB_PORT" >> .env
if [ -n "$F_MGMT_KEY" ]; then
  case "$F_MGMT_KEY" in *\ *|*"'"*|*\"*)
    echo "error: --mgmt-key path must not contain spaces/quotes" >&2
    exit 2 ;;
  esac
  echo "MGMT_KEY_PATH=$F_MGMT_KEY" >> .env
fi
if [ -z "${SENSOR_TOKEN:-}" ]; then
  echo "SENSOR_TOKEN=$(openssl rand -hex 24)" >> .env
fi
if [ -z "${DB_PASSWORD:-}" ]; then
  echo "DB_PASSWORD=$(openssl rand -hex 24)" >> .env
fi
if [ -z "${ADMIN_PASSWORD:-}" ]; then
  echo "ADMIN_PASSWORD=$(openssl rand -hex 16)" >> .env
fi
load_env
export SENSOR_TOKEN DB_PASSWORD ADMIN_PASSWORD TAG="${TAG:-latest}" SSH_HOST="${SSH_HOST:?set SSH_HOST in .env}"

# 2a. sensor-mgmt SSH key: stage the configured key for the server
# container (0600). Absent/empty key file means mgmt stays disabled.
if [ -n "${MGMT_KEY_PATH:-}" ]; then
  [ -f "$MGMT_KEY_PATH" ] || {
    echo "error: MGMT_KEY_PATH=$MGMT_KEY_PATH not found" >&2; exit 1; }
  cp -- "$MGMT_KEY_PATH" mgmt_key
fi
[ -f mgmt_key ] || : > mgmt_key
chmod 600 mgmt_key
if [ -s mgmt_key ]; then export MGMT_ENABLED=true
else export MGMT_ENABLED=false; fi

# 2b. NFS blob store (opt-in): pull NFS tooling, allow containers to use
# NFS, mount the export, persist it in fstab, point BLOB_MOUNT at it.
[ -n "$F_NFS_EXPORT" ] && echo "NFS_EXPORT=$F_NFS_EXPORT" >> .env
[ -n "$F_NFS_MOUNTPOINT" ] && echo "NFS_MOUNTPOINT=$F_NFS_MOUNTPOINT" >> .env
load_env
if [ -n "${NFS_EXPORT:-}" ]; then
  case "$NFS_EXPORT" in
    *:*/*) ;;
    *) echo "error: --nfs-export must be HOST:/PATH, got '$NFS_EXPORT'" >&2
       exit 2 ;;
  esac
  MP="${NFS_MOUNTPOINT:-/var/lib/carbide/blobs}"
  case "$MP" in *\ *|*"'"*|*\"*)
    echo "error: mountpoint must not contain spaces/quotes: '$MP'" >&2
    exit 2 ;;
  esac
  command -v mount.nfs >/dev/null || dnf install -y nfs-utils
  command -v setsebool >/dev/null || dnf install -y policycoreutils
  setsebool -P virt_use_nfs 1
  mkdir -p "$MP"
  FSTAB_LINE="$NFS_EXPORT $MP nfs defaults,_netdev 0 0"
  if ! grep -qF -- "$FSTAB_LINE" /etc/fstab; then
    [ -f /etc/fstab.carbide-bak ] || cp /etc/fstab /etc/fstab.carbide-bak
    awk -v mp="$MP" '$2 != mp' /etc/fstab > /etc/fstab.carbide-tmp
    cat /etc/fstab.carbide-tmp > /etc/fstab
    rm -f /etc/fstab.carbide-tmp
    echo "$FSTAB_LINE" >> /etc/fstab
  fi
  mountpoint -q "$MP" || mount "$MP" || {
    echo "error: cannot mount $NFS_EXPORT on $MP" >&2; exit 1; }
  grep -qF -- "BLOB_MOUNT=$MP:/var/lib/carbide/blobs" .env || \
    echo "BLOB_MOUNT=$MP:/var/lib/carbide/blobs" >> .env
  load_env
fi

# 3. pull images (with --skip-pull, `up` fetches missing stack images but
# the honeypot must already be local: it runs on the HOST, beside the stack).
if [ "$SKIP_PULL" -eq 0 ]; then
  podman pull "quay.io/sigaint/carbide-honeypot:$TAG"
  podman pull "quay.io/sigaint/carbide:$TAG"
  podman pull "quay.io/sigaint/carbide-squid:$TAG"
  podman pull docker.io/library/postgres:16
fi

# 4. render config + start (clear a directory shadow an old compose run
# may have auto-created at the config path)
if [ -d config.toml ]; then
  rmdir config.toml 2>/dev/null || {
    echo "error: ./config.toml is a non-empty directory; remove it" >&2
    exit 1; }
fi
envsubst < config.toml.tmpl > config.toml
chmod 600 config.toml
$COMPOSE up -d
# Recreate the server on every run: picks up the re-rendered config,
# re-binds a recreated host socket, and unwedges a container created
# against a stale mount (crun "Not a directory"). Deps stay untouched.
$COMPOSE up -d --force-recreate --no-deps server

# 5. firewall: API + console ports to sensor/VPN subnets only (never
# the internet)
if [ "$SKIP_FIREWALL" -eq 0 ] && [ "${#ALLOW_SUBNETS[@]}" -gt 0 ]; then
  if ! command -v firewall-cmd >/dev/null; then
    echo "warning: firewall-cmd missing, skipping firewall rules" >&2
  else
    systemctl enable --now firewalld >/dev/null 2>&1 || true
    for port in "${API_PORT:-8440}" "${WEB_PORT:-8080}"; do
      for net in "${ALLOW_SUBNETS[@]}"; do
        rule="rule family=\"ipv4\" source address=\"$net\" port port=\"$port\" protocol=\"tcp\" accept"
        firewall-cmd --query-rich-rule="$rule" >/dev/null || \
          firewall-cmd --permanent --add-rich-rule="$rule"
      done
    done
    firewall-cmd --reload >/dev/null
  fi
fi
# Loopback and the carbide gateway (container-only, set up above with a
# fixed address) need no firewall rules; anything else should be fenced.
case "${API_BIND:-127.0.0.1}" in
  127.*|::1|10.89.0.1) ;;
  *) [ "${#ALLOW_SUBNETS[@]}" -gt 0 ] || \
    echo "warning: API bound to $API_BIND with no --allow-subnet rules" >&2 ;;
esac
case "${WEB_BIND:-10.89.0.1}" in
  127.*|::1|10.89.0.1) ;;
  *) [ "${#ALLOW_SUBNETS[@]}" -gt 0 ] || \
    echo "warning: console bound to $WEB_BIND with no --allow-subnet rules" >&2 ;;
esac

# 6. wait for the API, ensure the console admin, then report
READY=0
for _ in $(seq 1 60); do
  if (exec 3<>"/dev/tcp/${API_BIND:-127.0.0.1}/${API_PORT:-8440}") 2>/dev/null; then
    exec 3>&- 3<&-
    READY=1
    break
  fi
  sleep 2
done
if [ "$READY" -eq 0 ]; then
  echo "error: API never came up on ${API_BIND:-127.0.0.1}:${API_PORT:-8440}" >&2
  $COMPOSE logs server | tail -20 >&2
  exit 1
fi
$COMPOSE exec -T -e "CARBIDE_ADMIN_PASSWORD=$ADMIN_PASSWORD" server \
  carbide-server -c /etc/carbide/config.toml --ensure-admin admin || {
  echo "error: console admin bootstrap failed" >&2; exit 1; }
echo "server stack up. sensor token (copy to each sensor's .env):"
echo "  SENSOR_TOKEN=$SENSOR_TOKEN"
echo "console: http://${WEB_BIND:-10.89.0.1}:${WEB_PORT:-8080} (admin / ADMIN_PASSWORD in .env)"
echo "  ADMIN_PASSWORD=$ADMIN_PASSWORD"
echo "logs: $COMPOSE logs -f server | status: $COMPOSE ps"
