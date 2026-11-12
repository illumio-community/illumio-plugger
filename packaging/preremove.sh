#!/bin/sh
# Stop the service on package removal (not on upgrade). The plugger user and
# /var/lib/plugger are kept so a reinstall finds its config and data.
case "$1" in
    remove|purge|0)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop plugger >/dev/null 2>&1 || true
            systemctl disable plugger >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0
