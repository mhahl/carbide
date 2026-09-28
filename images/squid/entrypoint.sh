#!/usr/bin/env bash
# Squid container entrypoint: mint the dummy splice cert if missing (it is
# never served — every TLS connection is spliced, never bumped), validate
# the config, then run in the foreground.
set -euo pipefail

if [ ! -f /etc/squid/splice-dummy.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -subj /CN=carbide-splice \
    -keyout /etc/squid/splice-dummy.pem \
    -out /etc/squid/splice-dummy.pem
fi

/usr/sbin/squid -k parse -f /etc/squid/squid.conf
exec /usr/sbin/squid -N -d 1 -f /etc/squid/squid.conf
