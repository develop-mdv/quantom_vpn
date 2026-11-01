#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/setup_admin.sh"
[[ "$(id -u)" == 0 ]] || fail "Run certificate renewal as root."
CONFIG="${OMEGA_ENV_FILE:-/etc/default/omega-server}"
if [[ -f "$CONFIG" ]]; then
    set -a
    source "$CONFIG"
    set +a
fi
[[ -n "${OMEGA_ADMIN_TLS_CERT:-}" && -n "${OMEGA_ADMIN_TLS_KEY:-}" ]] || exit 0
CERT_DIR="$(dirname "$OMEGA_ADMIN_TLS_CERT")"
[[ "$OMEGA_ADMIN_TLS_CERT" == "$CERT_DIR/cert.der" && "$OMEGA_ADMIN_TLS_KEY" == "$CERT_DIR/key.der" ]] || fail "Automatic renewal expects managed cert.der/key.der paths."
ensure_admin_certificate "$CERT_DIR" "$(detect_public_host)"
if [[ "$CERT_RENEWED" == 1 ]]; then
    echo "[INFO] Admin HTTPS certificate renewed (valid for 825 days)."
    if [[ "${1:-}" != "--before-start" ]] && systemctl is-active --quiet "${OMEGA_SERVICE_NAME:-omega-server}"; then
        systemctl try-restart "${OMEGA_SERVICE_NAME:-omega-server}"
    fi
fi
