#!/bin/sh
set -e

# Stop only on full removal (deb: "remove"/"purge", rpm: arg "$1" = "0")
if [ "$1" = "remove" ] || [ "$1" = "purge" ] || [ "$1" = "0" ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl stop ducksecrets.service >/dev/null 2>&1 || true
        systemctl disable ducksecrets.service >/dev/null 2>&1 || true
    fi
fi
