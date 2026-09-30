#!/bin/sh
# Honeypot container entrypoint: unique host keys per container, session user
# password from $CARBIDE_PASSWORD, httpd + mariadb services, then sshd in
# the foreground.
set -eu

# Generate host keys on first boot so every affinity container presents
# unique keys (nothing is baked into the image).
ssh-keygen -A >/dev/null 2>&1

if [ -n "${CARBIDE_PASSWORD:-}" ]; then
    echo "honey:${CARBIDE_PASSWORD}" | chpasswd
else
    passwd -l honey >/dev/null 2>&1 || true
fi

# Web stack: httpd starts instantly; mariadb initializes on first boot
# (flag-guarded) in the background so sshd never waits on it.
mkdir -p /run/httpd
/usr/sbin/httpd -k start >/dev/null 2>&1 || true
(
    mkdir -p /var/lib/mysql /var/run/mysqld
    chown mysql:mysql /var/lib/mysql /var/run/mysqld
    if [ ! -f /var/lib/mysql/.carbide-seeded ]; then
        mysqld --initialize-insecure --user=mysql >/dev/null 2>&1
    fi
    /usr/sbin/mysqld --daemonize --user=mysql >/dev/null 2>&1
    for _ in $(seq 1 30); do
        if mysqladmin --silent ping >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    if [ ! -f /var/lib/mysql/.carbide-seeded ] \
        && mysqladmin --silent ping >/dev/null 2>&1; then
        mysql -u root < /usr/share/carbide/mysql-init.sql
        mysql -u root wordpress < /var/backups/mysql/wordpress-2026-08-30.sql
        mysql -u root shop < /home/honey/shop_backup.sql
        touch /var/lib/mysql/.carbide-seeded
    fi
) >/dev/null 2>&1 &

# Explicit-proxy mode: container env never reaches sshd sessions, so stamp
# the proxy into sshd_config (SetEnv applies to every session, exec included).
if [ -n "${HTTP_PROXY:-}" ]; then
    # NB: sshd uses the FIRST value of a repeated keyword: one line.
    echo "SetEnv HTTP_PROXY=${HTTP_PROXY} HTTPS_PROXY=${HTTPS_PROXY:-$HTTP_PROXY} http_proxy=${http_proxy:-$HTTP_PROXY} https_proxy=${https_proxy:-${HTTPS_PROXY:-$HTTP_PROXY}}" >> /etc/ssh/sshd_config
fi

exec /usr/sbin/sshd -D -e
