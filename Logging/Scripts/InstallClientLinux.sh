#!/usr/bin/env bash
# Installs the Velociraptor CLIENT as a systemd service (Debian, Fedora, other systemd distros).
#
# Put these next to the script, or pass paths:
#   - the Linux binary    (velociraptor-v0.77.3-linux-amd64)
#   - client.config.yaml  (from the server's data folder)
#
# Usage:  sudo bash Install-VelociraptorClient.sh [binary] [client.config.yaml]
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC="${1:-}"
if [[ -z "$BIN_SRC" ]]; then
    BIN_SRC="$(find "$HERE" -maxdepth 1 -type f -name 'velociraptor*linux-amd64*' ! -name '*.sig' | head -n1)"
fi
CFG_SRC="${2:-$HERE/client.config.yaml}"

[[ -n "$BIN_SRC" && -f "$BIN_SRC" ]] || { echo "Velociraptor Linux binary not found. Pass its path as the first argument." >&2; exit 1; }
[[ -f "$CFG_SRC" ]] || { echo "client config not found: $CFG_SRC" >&2; exit 1; }

# Safety checks
[[ "$(head -c4 "$BIN_SRC" | tail -c3)" == "ELF" ]] || { echo "$BIN_SRC is not a Linux binary (wrong download?)." >&2; exit 1; }
if grep -q 'PRIVATE KEY' "$CFG_SRC"; then
    echo "REFUSING: $CFG_SRC contains a private key. That looks like the SERVER config." >&2
    echo "Only distribute client.config.yaml." >&2
    exit 1
fi
[[ "$(uname -m)" == "x86_64" ]] || echo "WARNING: this is $(uname -m), but the amd64 binary was expected."

echo "SHA256: $(sha256sum "$BIN_SRC" | cut -d' ' -f1)"

# Install
systemctl stop velociraptor_client 2>/dev/null || true
install -m 0755 -o root -g root "$BIN_SRC" /usr/local/bin/velociraptor
install -d -m 0700 -o root -g root /etc/velociraptor
install -m 0600 -o root -g root "$CFG_SRC" /etc/velociraptor/client.config.yaml
command -v restorecon >/dev/null 2>&1 && restorecon -R /usr/local/bin/velociraptor /etc/velociraptor || true

/usr/local/bin/velociraptor version | head -n3

# Connectivity check to the server named in the config
URL="$(grep -m1 -oE 'https?://[^/ "]+' /etc/velociraptor/client.config.yaml || true)"
if [[ -n "$URL" ]]; then
    HP="${URL#*//}"; H="${HP%%:*}"; P="${HP##*:}"; [[ "$P" == "$HP" ]] && P=443
    if timeout 5 bash -c "exec 3<>/dev/tcp/$H/$P" 2>/dev/null; then
        echo "Server reachable: $H:$P"
    else
        echo "WARNING: cannot reach $H:$P right now (firewall, route, or server down). Installing anyway." >&2
    fi
fi

# systemd unit
cat > /etc/systemd/system/velociraptor_client.service <<'EOF'
[Unit]
Description=Velociraptor client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/velociraptor --config /etc/velociraptor/client.config.yaml client -v
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/velociraptor_client.service

systemctl daemon-reload
systemctl enable --now velociraptor_client
sleep 5

if systemctl is-active --quiet velociraptor_client; then
    echo "OK: velociraptor_client is running. Check the host in the server GUI (search bar > Show All)."
else
    echo "FAILED to start. Recent log:" >&2
    journalctl -u velociraptor_client -n 20 --no-pager >&2
    exit 1
fi