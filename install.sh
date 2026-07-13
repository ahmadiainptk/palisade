#!/bin/bash
set -e
BIN="/usr/local/bin/palisade"
SERVICE="/etc/systemd/system/palisade.service"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with: sudo ./install.sh"
    exit 1
fi

echo "==> Installing Palisade to $BIN"
cp "$SCRIPT_DIR/palisade" "$BIN"
chmod 755 "$BIN"

echo "==> Installing systemd service"
cp "$SCRIPT_DIR/palisade.service" "$SERVICE"
systemctl daemon-reload

echo ""
echo "Done!"
echo "  Web UI:  http://127.0.0.1:8453"
echo "  Start:   sudo systemctl enable --now palisade"
echo "  Stop:    sudo systemctl stop palisade"
echo "  Status:  sudo systemctl status palisade"
echo "  Logs:    journalctl -u palisade -f"
