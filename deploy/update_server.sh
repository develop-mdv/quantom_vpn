#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <path_to_new_omega_server_binary> [path_to_systemd_unit_file]"
  exit 1
fi

NEW_BIN="$1"
NEW_UNIT="${2:-}"
SERVICE_NAME="${OMEGA_SERVICE_NAME:-omega-server}"
INSTALL_DIR="${OMEGA_INSTALL_DIR:-/opt/omega}"
RELEASES_DIR="$INSTALL_DIR/releases"
TARGET_LINK="$INSTALL_DIR/omega-server"
KEEP_RELEASES="${OMEGA_KEEP_RELEASES:-5}"
RELEASE_ID="${OMEGA_RELEASE_ID:-$(date +%Y%m%d%H%M%S)}"
UNIT_PATH="/etc/systemd/system/$SERVICE_NAME.service"
PREVIOUS_UNIT=""

cleanup() {
  if [[ -n "$PREVIOUS_UNIT" && -f "$PREVIOUS_UNIT" ]]; then
    rm -f "$PREVIOUS_UNIT"
  fi
}
trap cleanup EXIT

if [[ ! -f "$NEW_BIN" ]]; then
  echo "[ERROR] Binary not found: $NEW_BIN"
  exit 1
fi

if [[ -n "$NEW_UNIT" && ! -f "$NEW_UNIT" ]]; then
  echo "[ERROR] Unit file not found: $NEW_UNIT"
  exit 1
fi

mkdir -p "$RELEASES_DIR"
chmod +x "$NEW_BIN"

NEW_RELEASE_BIN="$RELEASES_DIR/omega-server-$RELEASE_ID"
cp "$NEW_BIN" "$NEW_RELEASE_BIN"
chmod 755 "$NEW_RELEASE_BIN"

PREVIOUS_TARGET=""
if [[ -L "$TARGET_LINK" ]]; then
  PREVIOUS_TARGET="$(readlink -f "$TARGET_LINK" || true)"
elif [[ -f "$TARGET_LINK" ]]; then
  PREVIOUS_TARGET="$TARGET_LINK"
fi

if [[ -f "$UNIT_PATH" ]]; then
  PREVIOUS_UNIT="$(mktemp)"
  cp "$UNIT_PATH" "$PREVIOUS_UNIT"
fi

print_diagnostics() {
  echo "[INFO] systemd status for $SERVICE_NAME"
  systemctl --no-pager --full status "$SERVICE_NAME" || true

  echo "[INFO] Last logs for $SERVICE_NAME"
  journalctl -u "$SERVICE_NAME" -n 80 --no-pager || true
}

wait_for_active() {
  local attempts="${1:-20}"
  local delay="${2:-1}"
  local state=""

  for ((i = 1; i <= attempts; i++)); do
    state="$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"

    if [[ "$state" == "active" ]]; then
      return 0
    fi

    if [[ "$state" == "failed" || "$state" == "inactive" ]]; then
      break
    fi

    sleep "$delay"
  done

  echo "[ERROR] Service state after restart: ${state:-unknown}"
  return 1
}

rollback() {
  echo "[WARN] Rolling back deployment..."

  if [[ -n "$NEW_UNIT" && -n "$PREVIOUS_UNIT" && -f "$PREVIOUS_UNIT" ]]; then
    echo "[INFO] Restoring previous systemd unit"
    install -m 0644 "$PREVIOUS_UNIT" "$UNIT_PATH"
    systemctl daemon-reload || true
  fi

  if [[ -n "$PREVIOUS_TARGET" && -e "$PREVIOUS_TARGET" ]]; then
    ln -sfn "$PREVIOUS_TARGET" "$TARGET_LINK"
    if systemctl restart "$SERVICE_NAME"; then
      echo "[INFO] Rollback successful. Service restored to previous version."
    else
      echo "[ERROR] Rollback failed: cannot restart $SERVICE_NAME"
      print_diagnostics
    fi
  else
    echo "[ERROR] Rollback skipped: previous binary not found"
  fi
}

ln -sfn "$NEW_RELEASE_BIN" "$TARGET_LINK"

if [[ -n "$NEW_UNIT" ]]; then
  echo "[INFO] Installing systemd unit to $UNIT_PATH"
  install -m 0644 "$NEW_UNIT" "$UNIT_PATH"
  systemctl daemon-reload
fi

echo "[INFO] Restarting $SERVICE_NAME"
if ! systemctl restart "$SERVICE_NAME"; then
  echo "[ERROR] Service restart failed"
  print_diagnostics
  rollback
  exit 1
fi

if ! wait_for_active 20 1; then
  echo "[ERROR] Service is not active after restart"
  print_diagnostics
  rollback
  exit 1
fi

# Keep only last N releases
ls -1dt "$RELEASES_DIR"/omega-server-* 2>/dev/null | tail -n +$((KEEP_RELEASES + 1)) | xargs -r rm -f

echo "[INFO] Deployment successful"
systemctl --no-pager --full status "$SERVICE_NAME" | sed -n '1,20p'
