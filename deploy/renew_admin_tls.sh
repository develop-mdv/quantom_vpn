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
if [[ "${OMEGA_ADMIN_TLS_MODE:-letsencrypt}" == "letsencrypt" ]]; then
    [[ "$OMEGA_ADMIN_TLS_CERT" == "$CERT_DIR/fullchain.pem" && "$OMEGA_ADMIN_TLS_KEY" == "$CERT_DIR/privkey.pem" ]] || fail "Let's Encrypt renewal expects managed fullchain.pem/privkey.pem paths."
    # Request a background renewal on startup without blocking the VPN on the CA.
    if [[ "${1:-}" == "--before-start" ]]; then
        if ! pem_certificate_ready "$OMEGA_ADMIN_TLS_CERT" "$OMEGA_ADMIN_TLS_KEY" "$(detect_public_host)" 3600; then
            systemctl start --no-block omega-admin-tls-renew.service
        fi
        exit 0
    fi
else
    [[ "$OMEGA_ADMIN_TLS_CERT" == "$CERT_DIR/cert.der" && "$OMEGA_ADMIN_TLS_KEY" == "$CERT_DIR/key.der" ]] || fail "Self-signed renewal expects managed cert.der/key.der paths."
fi
ensure_admin_certificate "$CERT_DIR" "$(detect_public_host)"
if [[ "$CERT_RENEWED" == 1 ]]; then
    echo "[INFO] Admin HTTPS certificate renewed."
    if [[ "${OMEGA_ADMIN_TLS_HOT_RELOAD:-0}" == 1 ]]; then
        echo "[INFO] The admin listener loads the new certificate on the next connection; VPN sessions are preserved."
    elif [[ "${1:-}" != "--before-start" ]] && systemctl is-active --quiet "${OMEGA_SERVICE_NAME:-omega-server}"; then
        systemctl try-restart "${OMEGA_SERVICE_NAME:-omega-server}"
    fi
fi
