#!/usr/bin/env bash
# Carbide server setup: pull images, generate secrets, render config,
# open the firewall, start the compose stack. Idempotent — re-run to
# upgrade (after bumping TAG in .env) or to repair. Must run as root
# (rootful podman socket + firewall).
#
# Usage: ./setup.sh [--allow-subnet CIDR]... [--api-bind IP] [--ssh-host HOST]
#          [--tag TAG] [--skip-firewall] [--skip-pull]
set -euo pipefail

cd "$(dirname "$0")"

ALLOW_SUBNETS=()
API_BIND=""; SSH_HOST=""; TAG=""; SKIP_FIREWALL=0; SKIP_PULL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --allow-subnet) ALLOW_SUBNETS+=("$2"); shift 2 ;;
    --api-bind) API_BIND="$2"; shift 2 ;;
    --ssh-host) SSH_HOST="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --skip-firewall) SKIP_FIREWALL=1; shift ;;
    --skip-pull) SKIP_PULL=1; shift ;;
    *) echo "usage: $0 [--allow-subnet CIDR]... [--skip-firewall]" >&2; exit 2 ;;
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
[ -n "$API_BIND" ] && echo "API_BIND=$API_BIND" >> .env
[ -n "$SSH_HOST" ] && echo "SSH_HOST=$SSH_HOST" >> .env
[ -n "$TAG" ] && echo "TAG=$TAG" >> .env
if [ -z "${SENSOR_TOKEN:-}" ]; then
  echo "SENSOR_TOKEN=$(openssl rand -hex 24)" >> .env
fi
if [ -z "${DB_PASSWORD:-}" ]; then
  echo "DB_PASSWORD=$(openssl rand -hex 24)" >> .env
fi
load_env
export SENSOR_TOKEN DB_PASSWORD TAG="${TAG:-latest}" SSH_HOST="${SSH_HOST:?set SSH_HOST in .env}"

# 3. pull images (with --skip-pull, `up` fetches missing stack images but
# the honeypot must already be local: it runs on the HOST, beside the stack).
if [ "$SKIP_PULL" -eq 0 ]; then
  podman pull "quay.io/sigaint/carbide-honeypot:$TAG"
  podman pull "quay.io/sigaint/carbide:$TAG"
  podman pull "quay.io/sigaint/carbide-squid:$TAG"
  podman pull docker.io/library/postgres:16
fi

# 4. render config + start
envsubst < config.toml.tmpl > config.toml
chmod 600 config.toml
$COMPOSE up -d

# 5. firewall: API port to sensor/VPN subnets only (never the internet)
if [ "$SKIP_FIREWALL" -eq 0 ] && [ "${#ALLOW_SUBNETS[@]}" -gt 0 ]; then
  if ! command -v firewall-cmd >/dev/null; then
    echo "warning: firewall-cmd missing, skipping firewall rules" >&2
  else
    systemctl enable --now firewalld >/dev/null 2>&1 || true
    for net in "${ALLOW_SUBNETS[@]}"; do
      rule="rule family=\"ipv4\" source address=\"$net\" port port=\"${API_PORT:-8440}\" protocol=\"tcp\" accept"
      firewall-cmd --query-rich-rule="$rule" >/dev/null || \
        firewall-cmd --permanent --add-rich-rule="$rule"
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

# 6. wait for the API, then report
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
echo "server stack up. sensor token (copy to each sensor's .env):"
echo "  SENSOR_TOKEN=$SENSOR_TOKEN"
echo "logs: $COMPOSE logs -f server | status: $COMPOSE ps"
