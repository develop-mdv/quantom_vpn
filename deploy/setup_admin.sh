#!/usr/bin/env bash
set -euo pipefail

fail() { echo "[ERROR] $*" >&2; exit 1; }

set_config() {
    local config="$1" key="$2" value="$3" temporary
    [[ "$key" =~ ^OMEGA_[A-Z0-9_]+$ && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail "Invalid config setting."
    temporary="$(mktemp "${config}.XXXXXX")"
    awk -v key="$key" 'index($0, key "=") != 1 { print }' "$config" > "$temporary"
    printf '%s=%s\n' "$key" "$value" >> "$temporary"
    chmod 0600 "$temporary"
    mv -f -- "$temporary" "$config"
}

detect_public_host() {
    local host="${OMEGA_PUBLIC_HOST:-}" client client_port server ssh_port
    if [[ -z "$host" && -n "${OMEGA_CLIENT_SERVER:-}" ]]; then
        host="${OMEGA_CLIENT_SERVER%:*}"
        host="${host#[}"; host="${host%]}"
        if ! python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$host" 2>/dev/null; then host=""; fi
    fi
    if [[ -z "$host" ]]; then
        read -r client client_port server ssh_port <<< "${SSH_CONNECTION:-}"
        host="${server:-}"
    fi
    if [[ -z "$host" ]]; then
        host="$(curl --fail --silent --show-error --connect-timeout 5 --max-time 15 https://api64.ipify.org)" || fail "Set OMEGA_PUBLIC_HOST to the public VPS IP."
    fi
    # Only IP addresses are accepted here; this value is used in certificate SANs.
    python3 -c 'import ipaddress,sys; print(ipaddress.ip_address(sys.argv[1]))' "$host"
}

ensure_admin_certificate() {
    local cert_dir="$1" host="$2"
    install -d -m 0700 "$cert_dir"
    exec 9>"$cert_dir/renew.lock"
    flock -x 9
    CERT_RENEWED=0
    if [[ ! -f "$cert_dir/cert.der" || ! -f "$cert_dir/key.der" ]] || \
        ! openssl x509 -inform DER -in "$cert_dir/cert.der" -checkip "$host" -noout >/dev/null 2>&1 || \
        ! openssl x509 -inform DER -in "$cert_dir/cert.der" -checkend 2592000 -noout >/dev/null 2>&1; then
        local cert_temp
        cert_temp="$(mktemp -d "$cert_dir/.new-XXXXXX")"
        if ! openssl req -x509 -newkey rsa:3072 -nodes -days 825 \
            -subj "/CN=$host" -addext "subjectAltName=IP:$host" \
            -keyout "$cert_temp/key.pem" -out "$cert_temp/cert.pem" 2>/dev/null || \
            ! openssl x509 -in "$cert_temp/cert.pem" -outform DER -out "$cert_temp/cert.der" || \
            ! openssl pkcs8 -topk8 -nocrypt -in "$cert_temp/key.pem" -outform DER -out "$cert_temp/key.der"; then
            rm -rf -- "$cert_temp"
            fail "Could not create the HTTPS certificate."
        fi
        install -m 0600 "$cert_temp/key.der" "$cert_dir/key.der"
        install -m 0644 "$cert_temp/cert.der" "$cert_dir/cert.der"
        rm -rf -- "$cert_temp"
        CERT_RENEWED=1
    fi
    flock -u 9
    exec 9>&-
}

configure_admin() {
    local config="$1" state_dir="$2" binary="$3" credentials_output="$4"
    local host port cert_dir url_host client_host
    host="$(detect_public_host)"
    port="${OMEGA_ADMIN_HTTPS_PORT:-8443}"
    [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || fail "Invalid HTTPS admin port."
    [[ "$port" != "${OMEGA_TCP_PORT:-443}" ]] || fail "HTTPS admin port conflicts with the VPN TCP port."
    cert_dir="$state_dir/admin-tls"
    ensure_admin_certificate "$cert_dir" "$host"
    export OMEGA_ADMIN_AUTH_DB="$state_dir/admin-auth.json"
    (umask 077; "$binary" admin init_web > "$credentials_output")
    set_config "$config" OMEGA_PUBLIC_HOST "$host"
    set_config "$config" OMEGA_ADMIN_AUTH_DB "$OMEGA_ADMIN_AUTH_DB"
    set_config "$config" OMEGA_ADMIN_TLS_CERT "$cert_dir/cert.der"
    set_config "$config" OMEGA_ADMIN_TLS_KEY "$cert_dir/key.der"
    set_config "$config" OMEGA_ADMIN_WEB_BIND "[::]:$port"
    set_config "$config" OMEGA_ADMIN_WEB_PUBLIC 1
    set_config "$config" OMEGA_ADMIN_WEB_DISABLE 0
    set_config "$config" OMEGA_ADMIN_WEB_PORT "$port"
    set_config "$config" OMEGA_ADMIN_HTTPS_PORT "$port"
    client_host="$host"; url_host="$host"
    if [[ "$host" == *:* ]]; then client_host="[$host]"; url_host="[$host]"; fi
    if [[ -z "${OMEGA_CLIENT_SERVER:-}" ]]; then
        set_config "$config" OMEGA_CLIENT_SERVER "$client_host:${OMEGA_VPN_PORT:-443}"
    fi
    ADMIN_URL="https://$url_host:$port"
    export OMEGA_ADMIN_WEB_PUBLIC=1 OMEGA_ADMIN_WEB_PORT="$port"
}

setup_admin_main() {
    [[ "$(id -u)" == 0 ]] || fail "Run admin setup as root."
    local binary="${1:?Pass the new omega-server binary}" script_dir config install_dir state_dir output
    local requested_public_host="${OMEGA_PUBLIC_HOST:-}" requested_admin_port="${OMEGA_ADMIN_HTTPS_PORT:-}"
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    config="${OMEGA_ENV_FILE:-/etc/default/omega-server}"
    install_dir="${OMEGA_INSTALL_DIR:-/opt/omega}"
    state_dir="$install_dir/state"
    install -d -m 0700 "$state_dir"
    install -d -m 0755 "$(dirname "$config")"
    if [[ ! -e "$config" ]]; then install -m 0600 /dev/null "$config"; fi
    set -a
    source "$config"
    set +a
    if [[ -n "$requested_public_host" ]]; then export OMEGA_PUBLIC_HOST="$requested_public_host"; fi
    if [[ -n "$requested_admin_port" ]]; then export OMEGA_ADMIN_HTTPS_PORT="$requested_admin_port"; fi
    output="$(mktemp "$state_dir/.bootstrap-XXXXXX")"
    configure_admin "$config" "$state_dir" "$binary" "$output"
    if python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["created"] else 1)' "$output"; then
        install -m 0600 "$output" "$state_dir/admin-bootstrap.json"
        echo "[INFO] Initial admin credentials are in $state_dir/admin-bootstrap.json (root only)."
    fi
    rm -f -- "$output"
    if [[ "$script_dir" != "$install_dir" ]]; then
        install -m 0755 "$script_dir/setup_admin.sh" "$script_dir/renew_admin_tls.sh" "$install_dir/"
    fi
    install -m 0644 "$script_dir/omega-admin-tls-renew.service" "$script_dir/omega-admin-tls-renew.timer" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now omega-admin-tls-renew.timer
    echo "[INFO] Admin HTTPS and automatic certificate renewal configured: $ADMIN_URL"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    setup_admin_main "$@"
fi
