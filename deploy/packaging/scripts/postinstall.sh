#!/bin/sh
set -e

if ! getent group ducksecrets >/dev/null 2>&1; then
    groupadd --system ducksecrets 2>/dev/null || addgroup --system ducksecrets 2>/dev/null || true
fi

if ! getent passwd ducksecrets >/dev/null 2>&1; then
    useradd --system --gid ducksecrets --home-dir /var/lib/ducksecrets \
        --shell /usr/sbin/nologin --comment "Ducksecrets service" ducksecrets 2>/dev/null \
        || adduser --system --ingroup ducksecrets --home /var/lib/ducksecrets \
            --shell /sbin/nologin ducksecrets 2>/dev/null || true
fi

mkdir -p /var/lib/ducksecrets
chown ducksecrets:ducksecrets /var/lib/ducksecrets
chmod 0750 /var/lib/ducksecrets

if [ -x /usr/bin/ducksecretsd ] && [ ! -f /etc/ducksecrets/tls.crt ] && [ ! -f /etc/ducksecrets/tls.key ]; then
    /usr/bin/ducksecretsd tls init --cert /etc/ducksecrets/tls.crt --key /etc/ducksecrets/tls.key >/dev/null 2>&1 || true
fi

if [ -d /etc/ducksecrets ]; then
    chown root:ducksecrets /etc/ducksecrets || true
    chmod 0750 /etc/ducksecrets || true
fi
if [ -f /etc/ducksecrets/env ]; then
    chown root:ducksecrets /etc/ducksecrets/env || true
    chmod 0640 /etc/ducksecrets/env || true
fi
if [ -f /etc/ducksecrets/tls.crt ]; then
    chown root:ducksecrets /etc/ducksecrets/tls.crt || true
    chmod 0644 /etc/ducksecrets/tls.crt || true
fi
if [ -f /etc/ducksecrets/tls.key ]; then
    chown ducksecrets:ducksecrets /etc/ducksecrets/tls.key || true
    chmod 0600 /etc/ducksecrets/tls.key || true
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
