#!/usr/bin/env bash
# Build and push all carbide images. Run from the repo root:
#   ./images/build-push.sh [tag]        # default tag: version in pyproject.toml
# Requires: podman logged into quay.io (podman login quay.io).
set -euo pipefail

cd "$(dirname "$0")/.."

TAG="${1:-$(grep '^version' pyproject.toml | cut -d'"' -f2)}"
REG="quay.io/sigaint"
APPS=(carbide carbide-squid carbide-honeypot)

if ! podman login --get-login quay.io >/dev/null 2>&1; then
  echo "error: not logged into quay.io (run: podman login quay.io)" >&2
  exit 1
fi

podman build -t "$REG/carbide:$TAG" -t "$REG/carbide:latest" \
  -f images/carbide/Containerfile .
podman build -t "$REG/carbide-squid:$TAG" -t "$REG/carbide-squid:latest" \
  -f images/squid/Containerfile .
podman build -t "$REG/carbide-honeypot:$TAG" -t "$REG/carbide-honeypot:latest" \
  image/

for app in "${APPS[@]}"; do
  podman push "$REG/$app:$TAG"
  podman push "$REG/$app:latest"
done

echo "pushed: ${APPS[*]} at $TAG and latest"
