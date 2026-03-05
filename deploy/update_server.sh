#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <path_to_new_omega_server_binary>"
  exit 1
fi

NEW_BIN="$1"
SERVICE_NAME="${OMEGA_SERVICE_NAME:-omega-server}"
INSTALL_DIR="${OMEGA_INSTALL_DIR:-/opt/omega}"
RELEASES_DIR="$INSTALL_DIR/releases"
TARGET_LINK="$INSTALL_DIR/omega-server"
KEEP_RELEASES="${OMEGA_KEEP_RELEASES:-5}"
RELEASE_ID="${OMEGA_RELEASE_ID:-$(date +%Y%m%d%H%M%S)}"

if [[ ! -f "$NEW_BIN" ]]; then
  echo "[ERROR] Binary not found: $NEW_BIN"
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

rollback() {
  echo "[WARN] Rolling back deployment..."
  if [[ -n "$PREVIOUS_TARGET" && -e "$PREVIOUS_TARGET" ]]; then
    ln -sfn "$PREVIOUS_TARGET" "$TARGET_LINK"
    if systemctl restart "$SERVICE_NAME"; then
      echo "[INFO] Rollback successful. Service restored to previous version."
    else
      echo "[ERROR] Rollback failed: cannot restart $SERVICE_NAME"
    fi
  else
    echo "[ERROR] Rollback skipped: previous binary not found"
  fi
}

ln -sfn "$NEW_RELEASE_BIN" "$TARGET_LINK"

echo "[INFO] Restarting $SERVICE_NAME"
if ! systemctl restart "$SERVICE_NAME"; then
  echo "[ERROR] Service restart failed"
  rollback
  exit 1
fi

sleep 2
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
  echo "[ERROR] Service is not active after restart"
  rollback
  exit 1
fi

# Keep only last N releases
ls -1dt "$RELEASES_DIR"/omega-server-* 2>/dev/null | tail -n +$((KEEP_RELEASES + 1)) | xargs -r rm -f

echo "[INFO] Deployment successful"
systemctl --no-pager --full status "$SERVICE_NAME" | sed -n '1,20p'
