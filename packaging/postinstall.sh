#!/bin/sh
# Runs after the .deb/.rpm installs plugger. Creates the service user and its
# home; the service itself stays disabled until the operator enables it.
set -e

if ! getent group plugger >/dev/null 2>&1; then
    groupadd --system plugger
fi
if ! getent passwd plugger >/dev/null 2>&1; then
    nologin=$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)
    useradd --system --gid plugger --home-dir /var/lib/plugger --no-create-home \
        --shell "$nologin" --comment "Plugger service" plugger
fi

mkdir -p /var/lib/plugger/.plugger
chown -R plugger:plugger /var/lib/plugger
chmod 750 /var/lib/plugger

# The service talks to the Docker socket; join the docker group when there is one.
if getent group docker >/dev/null 2>&1; then
    usermod -aG docker plugger
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

cat <<'EOF'
plugger installed. To run it as a service:
  sudo -u plugger HOME=/var/lib/plugger plugger init
  sudo systemctl enable --now plugger
Dashboard: http://localhost:8800  (see /usr/lib/systemd/system/plugger.service to change the address)
EOF
