#!/usr/bin/env bash
# Carbide sensor setup: write .env, render config, pull the image, open the
# firewall, start the compose stack. Idempotent — re-run to upgrade (after
# bumping TAG in .env) or to repair. Root needed only for the firewall step.
#
# Usage: ./setup.sh --sensor-id ID --token TOKEN [--server-host HOST]
#          [--server-port 8440] [--listen-port 2222] [--tag latest]
#          [--skip-firewall] [--skip-pull]
# Anything not flagged falls back to .env (pre-seed it or accept the
# single-host defaults and pass only --sensor-id/--token).
set -euo pipefail

cd "$(dirname "$0")"

SERVER_HOST=""; SENSOR_ID=""; TOKEN=""; SERVER_PORT=""; LISTEN_PORT=""
TAG=""; SKIP_FIREWALL=0; SKIP_PULL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --server-host) SERVER_HOST="$2"; shift 2 ;;
    --sensor-id) SENSOR_ID="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --server-port) SERVER_PORT="$2"; shift 2 ;;
    --listen-port) LISTEN_PORT="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --skip-firewall) SKIP_FIREWALL=1; shift ;;
    --skip-pull) SKIP_PULL=1; shift ;;
    *) echo "usage: $0 --sensor-id ID --token TOKEN [--server-host HOST] [...]" >&2
       exit 2 ;;
  esac
done

for cmd in podman envsubst; do
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

[ -f .env ] || cp .env.example .env
chmod 600 .env

# Apply CLI overrides (append wins: load_env keeps the LAST value per key).
# Only explicit flags append, so a pre-seeded .env is never clobbered.
[ -n "$SERVER_HOST" ] && echo "SERVER_HOST=$SERVER_HOST" >> .env
[ -n "$SERVER_PORT" ] && echo "SERVER_PORT=$SERVER_PORT" >> .env
[ -n "$SENSOR_ID" ] && echo "SENSOR_ID=$SENSOR_ID" >> .env
[ -n "$TOKEN" ] && echo "SENSOR_TOKEN=$TOKEN" >> .env
[ -n "$LISTEN_PORT" ] && echo "LISTEN_PORT=$LISTEN_PORT" >> .env
[ -n "$TAG" ] && echo "TAG=$TAG" >> .env

load_env() {  # literal KEY=value lines (no bash word-splitting).
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

: "${SERVER_HOST:?set SERVER_HOST in .env or --server-host}"
: "${SENSOR_ID:?set SENSOR_ID in .env or --sensor-id}"
: "${SENSOR_TOKEN:?set SENSOR_TOKEN in .env or --token}"
case "$SENSOR_TOKEN" in
  CHANGE-ME) echo "error: set a real SENSOR_TOKEN (--token ...)" >&2; exit 1 ;;
esac
case "$SENSOR_TOKEN" in *[!A-Za-z0-9_.-]*|"")
  echo "error: token must be [A-Za-z0-9_.-] (hex from server setup)" >&2
  exit 1 ;;
esac
export SERVER_HOST SERVER_PORT SENSOR_ID SENSOR_TOKEN

if [ "$SKIP_PULL" -eq 0 ]; then
  podman pull "quay.io/sigaint/carbide:$TAG"
fi
envsubst < config.toml.tmpl > config.toml
chmod 600 config.toml
$COMPOSE up -d

if [ "$SKIP_FIREWALL" -eq 0 ]; then
  if [ "$(id -u)" -ne 0 ]; then
    echo "warning: not root, skipping firewall (open $LISTEN_PORT/tcp)" >&2
  elif ! command -v firewall-cmd >/dev/null; then
    echo "warning: firewall-cmd missing, skipping firewall rules" >&2
  else
    systemctl enable --now firewalld >/dev/null 2>&1 || true
    firewall-cmd --query-port="$LISTEN_PORT/tcp" >/dev/null || \
      firewall-cmd --permanent --add-port="$LISTEN_PORT/tcp"
    firewall-cmd --reload >/dev/null
  fi
fi

READY=0
for _ in $(seq 1 30); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$LISTEN_PORT") 2>/dev/null; then
    exec 3>&- 3<&-
    READY=1
    break
  fi
  sleep 2
done
if [ "$READY" -eq 0 ]; then
  echo "error: sensor never came up on port $LISTEN_PORT" >&2
  $COMPOSE logs sensor | tail -20 >&2
  exit 1
fi
echo "sensor $SENSOR_ID up on port $LISTEN_PORT, linked to $SERVER_HOST."
echo "test: ssh -p $LISTEN_PORT root@<this-host>  (then check server reports)"
echo "logs: $COMPOSE logs -f sensor | spool: $COMPOSE exec sensor ls /var/lib/carbide/spool"
