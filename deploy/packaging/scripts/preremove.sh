#!/bin/sh

# Stop only on full removal (deb: "remove"/"purge", rpm: "0", arch: pkgver starting with digit)
case "${1:-}" in
    remove|purge|0|[0-9]*)
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            systemctl stop ducksecrets.service >/dev/null 2>&1 || true
            systemctl disable ducksecrets.service >/dev/null 2>&1 || true
        fi
        ;;
esac
