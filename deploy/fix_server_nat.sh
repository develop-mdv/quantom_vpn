#!/usr/bin/env bash
set -euo pipefail

# Quick server fix: disable UFW (which blocks FORWARD), run the real nftables setup_nat.sh,
# and restart omega-server.
#
# Usage (from your local machine):
#   scp deploy/setup_nat.sh deploy/fix_server_nat.sh root@72.56.88.224:/root/
#   ssh root@72.56.88.224 "bash /root/fix_server_nat.sh"

echo "[INFO] === Omega VPN Server NAT Fix ==="

# Step 1: Disable UFW if it's active (the old setup_nat.sh enabled it, blocking FORWARD)
if command -v ufw >/dev/null 2>&1; then
  UFW_STATUS="$(ufw status 2>/dev/null | head -1 || true)"
  if echo "$UFW_STATUS" | grep -qi "active"; then
    echo "[INFO] Disabling UFW (it blocks FORWARD chain by default)"
    ufw disable || true
  else
    echo "[INFO] UFW is not active, skipping"
  fi
else
  echo "[INFO] UFW not installed, skipping"
fi

# Step 2: Ensure IP forwarding is on
sysctl -q -w net.ipv4.ip_forward=1

# Step 3: Run the nftables-based setup_nat.sh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NAT_SCRIPT="${SCRIPT_DIR}/setup_nat.sh"

if [[ ! -f "$NAT_SCRIPT" ]]; then
  NAT_SCRIPT="/root/setup_nat.sh"
fi

if [[ ! -f "$NAT_SCRIPT" ]]; then
  echo "[ERROR] setup_nat.sh not found at $SCRIPT_DIR or /root"
  echo "[ERROR] Please scp deploy/setup_nat.sh to the server first"
  exit 1
fi

echo "[INFO] Running nftables setup: $NAT_SCRIPT"
bash "$NAT_SCRIPT"

# Step 4: Install setup_nat.sh to /opt/omega for future deploys
INSTALL_DIR="${OMEGA_INSTALL_DIR:-/opt/omega}"
mkdir -p "$INSTALL_DIR"
if [[ "$NAT_SCRIPT" != "$INSTALL_DIR/setup_nat.sh" ]]; then
  install -m 0755 "$NAT_SCRIPT" "$INSTALL_DIR/setup_nat.sh"
  echo "[INFO] Installed setup_nat.sh to $INSTALL_DIR/setup_nat.sh"
fi

# Step 5: Restart omega-server to pick up clean state
SERVICE_NAME="${OMEGA_SERVICE_NAME:-omega-server}"
if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
  echo "[INFO] Restarting $SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"
  sleep 2
  systemctl --no-pager status "$SERVICE_NAME" | head -5
else
  echo "[WARN] $SERVICE_NAME is not running"
fi

# Step 6: Verify
echo ""
echo "[INFO] === Verification ==="
echo "[CHECK] IP forwarding:"
sysctl net.ipv4.ip_forward

echo "[CHECK] nftables omega_vpn table:"
if nft list table inet omega_vpn >/dev/null 2>&1; then
  echo "  OK — omega_vpn table exists"
  nft list chain inet omega_vpn mss_clamp 2>/dev/null | grep -i "mss" || true
  nft list chain inet omega_vpn forward 2>/dev/null | grep -c "accept" | xargs -I{} echo "  forward rules: {} accept entries"
else
  echo "  FAIL — omega_vpn table missing!"
fi

echo "[CHECK] NAT masquerade:"
if nft list table ip omega_vpn_nat >/dev/null 2>&1; then
  echo "  OK — omega_vpn_nat table exists"
  nft list table ip omega_vpn_nat 2>/dev/null | grep masquerade || true
else
  echo "  FAIL — omega_vpn_nat table missing!"
fi

echo "[CHECK] UFW status:"
if command -v ufw >/dev/null 2>&1; then
  ufw status | head -1
else
  echo "  UFW not installed"
fi

echo ""
echo "[INFO] Done. Connect from client and test:"
echo "  cargo run --release -p omega-client-app -- connect"
echo "  curl https://api.ipify.org"
