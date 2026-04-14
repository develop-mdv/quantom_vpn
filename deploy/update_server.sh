#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <path_to_new_omega_server_binary> [path_to_systemd_unit_file] [path_to_alert_rules_file] [path_to_setup_nat_script]"
  exit 1
fi

NEW_BIN="$1"
NEW_UNIT="${2:-}"
NEW_ALERTS="${3:-}"
NEW_NAT="${4:-}"
SERVICE_NAME="${OMEGA_SERVICE_NAME:-omega-server}"
INSTALL_DIR="${OMEGA_INSTALL_DIR:-/opt/omega}"
SETUP_NAT="${OMEGA_SETUP_NAT:-$INSTALL_DIR/setup_nat.sh}"
ALERTS_DEST="${OMEGA_ALERTS_DEST:-$INSTALL_DIR/omega-alerts.yml}"
PROMETHEUS_SERVICE_NAME="${OMEGA_PROMETHEUS_SERVICE_NAME:-}"
RELEASES_DIR="$INSTALL_DIR/releases"
TARGET_LINK="$INSTALL_DIR/omega-server"
KEEP_RELEASES="${OMEGA_KEEP_RELEASES:-5}"
RELEASE_ID="${OMEGA_RELEASE_ID:-$(date +%Y%m%d%H%M%S)}"
CANARY_ATTEMPTS="${OMEGA_CANARY_ATTEMPTS:-12}"
CANARY_DELAY_SECS="${OMEGA_CANARY_DELAY_SECS:-5}"
UNIT_PATH="/etc/systemd/system/$SERVICE_NAME.service"
PREVIOUS_UNIT=""
PREVIOUS_ALERTS=""

export_runtime_env_defaults() {
  export OMEGA_IDENTITY_DB="${OMEGA_IDENTITY_DB:-$INSTALL_DIR/state/identity.json}"
  export OMEGA_SESSION_SNAPSHOT="${OMEGA_SESSION_SNAPSHOT:-$INSTALL_DIR/state/sessions.json}"
  export OMEGA_RUNTIME_SNAPSHOT="${OMEGA_RUNTIME_SNAPSHOT:-$INSTALL_DIR/state/runtime.json}"
  export OMEGA_OBSERVABILITY_SNAPSHOT="${OMEGA_OBSERVABILITY_SNAPSHOT:-$INSTALL_DIR/state/observability.json}"
  export OMEGA_TRACE_JOURNAL="${OMEGA_TRACE_JOURNAL:-$INSTALL_DIR/state/trace.ndjson}"
  export OMEGA_ADMIN_COMMANDS="${OMEGA_ADMIN_COMMANDS:-$INSTALL_DIR/state/admin_commands.ndjson}"
}

cleanup() {
  if [[ -n "$PREVIOUS_UNIT" && -f "$PREVIOUS_UNIT" ]]; then
    rm -f "$PREVIOUS_UNIT"
  fi
  if [[ -n "$PREVIOUS_ALERTS" && -f "$PREVIOUS_ALERTS" ]]; then
    rm -f "$PREVIOUS_ALERTS"
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

if [[ -n "$NEW_ALERTS" && ! -f "$NEW_ALERTS" ]]; then
  echo "[ERROR] Alert rules file not found: $NEW_ALERTS"
  exit 1
fi

if [[ -n "$NEW_NAT" && ! -f "$NEW_NAT" ]]; then
  echo "[ERROR] setup_nat script not found: $NEW_NAT"
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

if [[ -n "$NEW_ALERTS" && -f "$ALERTS_DEST" ]]; then
  PREVIOUS_ALERTS="$(mktemp)"
  cp "$ALERTS_DEST" "$PREVIOUS_ALERTS"
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

reload_prometheus_alerts() {
  if [[ -z "$PROMETHEUS_SERVICE_NAME" ]]; then
    return 0
  fi

  echo "[INFO] Reloading Prometheus service $PROMETHEUS_SERVICE_NAME"
  if systemctl reload "$PROMETHEUS_SERVICE_NAME"; then
    return 0
  fi

  echo "[WARN] Prometheus reload is unavailable, trying restart"
  systemctl restart "$PROMETHEUS_SERVICE_NAME"
}

install_alerts() {
  if [[ -z "$NEW_ALERTS" ]]; then
    return 0
  fi

  mkdir -p "$(dirname "$ALERTS_DEST")"
  install -m 0644 "$NEW_ALERTS" "$ALERTS_DEST"
  echo "[INFO] Installed alert rules to $ALERTS_DEST"
  reload_prometheus_alerts
}

rollback() {
  echo "[WARN] Rolling back deployment..."

  if [[ -n "$NEW_UNIT" && -n "$PREVIOUS_UNIT" && -f "$PREVIOUS_UNIT" ]]; then
    echo "[INFO] Restoring previous systemd unit"
    install -m 0644 "$PREVIOUS_UNIT" "$UNIT_PATH"
    systemctl daemon-reload || true
  fi

  if [[ -n "$NEW_ALERTS" ]]; then
    if [[ -n "$PREVIOUS_ALERTS" && -f "$PREVIOUS_ALERTS" ]]; then
      echo "[INFO] Restoring previous alert rules"
      mkdir -p "$(dirname "$ALERTS_DEST")"
      install -m 0644 "$PREVIOUS_ALERTS" "$ALERTS_DEST"
      reload_prometheus_alerts || true
    else
      echo "[INFO] Removing newly installed alert rules"
      rm -f "$ALERTS_DEST"
      reload_prometheus_alerts || true
    fi
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

run_canary_guard() {
  local attempts="${1:-$CANARY_ATTEMPTS}"
  local delay="${2:-$CANARY_DELAY_SECS}"

  export_runtime_env_defaults
  echo "[INFO] Expecting observability snapshot at $OMEGA_OBSERVABILITY_SNAPSHOT"
  echo "[INFO] Running rollout guard canary checks"
  for ((i = 1; i <= attempts; i++)); do
    if "$TARGET_LINK" admin assert_rollout_guard; then
      echo "[INFO] Rollout guard passed on attempt $i/$attempts"
      return 0
    fi

    echo "[WARN] Rollout guard not healthy yet (attempt $i/$attempts)"
    "$TARGET_LINK" admin show_rollout_guard || true
    sleep "$delay"
  done

  echo "[ERROR] Rollout guard failed after $attempts attempts"
  return 1
}

ln -sfn "$NEW_RELEASE_BIN" "$TARGET_LINK"

if [[ -n "$NEW_UNIT" ]]; then
  echo "[INFO] Installing systemd unit to $UNIT_PATH"
  install -m 0644 "$NEW_UNIT" "$UNIT_PATH"
  systemctl daemon-reload
fi

if [[ -n "$NEW_ALERTS" ]]; then
  echo "[INFO] Installing alert rules to $ALERTS_DEST"
  if ! install_alerts; then
    echo "[ERROR] Alert rules installation failed"
    rollback
    exit 1
  fi
fi

# Install setup_nat.sh to INSTALL_DIR if provided
if [[ -n "$NEW_NAT" ]]; then
  install -m 0755 "$NEW_NAT" "$INSTALL_DIR/setup_nat.sh"
  echo "[INFO] Installed setup_nat.sh to $INSTALL_DIR/setup_nat.sh"
fi

# Ensure NAT/forwarding rules are applied (idempotent)
if [[ -f "$SETUP_NAT" ]]; then
  echo "[INFO] Applying NAT/forwarding rules via $SETUP_NAT"
  if ! bash "$SETUP_NAT"; then
    echo "[WARN] setup_nat.sh returned non-zero; continuing with deploy"
  fi
else
  echo "[WARN] $SETUP_NAT not found, skipping NAT setup"
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

if ! run_canary_guard "$CANARY_ATTEMPTS" "$CANARY_DELAY_SECS"; then
  echo "[ERROR] Canary rollout guard rejected the release"
  print_diagnostics
  rollback
  exit 1
fi

# Keep only last N releases
ls -1dt "$RELEASES_DIR"/omega-server-* 2>/dev/null | tail -n +$((KEEP_RELEASES + 1)) | xargs -r rm -f

echo "[INFO] Deployment successful"
systemctl --no-pager --full status "$SERVICE_NAME" | sed -n '1,20p'










