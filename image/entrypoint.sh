#!/bin/sh
# Honeypot container entrypoint: unique host keys per container, session user
# password from $CARBIDE_PASSWORD, then sshd in the foreground.
set -eu

# Generate host keys on first boot so every affinity container presents
# unique keys (nothing is baked into the image).
ssh-keygen -A >/dev/null 2>&1

if [ -n "${CARBIDE_PASSWORD:-}" ]; then
    echo "honey:${CARBIDE_PASSWORD}" | chpasswd
else
    passwd -l honey >/dev/null 2>&1 || true
fi

# Explicit-proxy mode: container env never reaches sshd sessions, so stamp
# the proxy into sshd_config (SetEnv applies to every session, exec included).
if [ -n "${HTTP_PROXY:-}" ]; then
    # NB: sshd uses the FIRST value of a repeated keyword: one line.
    echo "SetEnv HTTP_PROXY=${HTTP_PROXY} HTTPS_PROXY=${HTTPS_PROXY:-$HTTP_PROXY} http_proxy=${http_proxy:-$HTTP_PROXY} https_proxy=${https_proxy:-${HTTPS_PROXY:-$HTTP_PROXY}}" >> /etc/ssh/sshd_config
fi

exec /usr/sbin/sshd -D -e
