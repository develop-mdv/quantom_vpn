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

ensure_self_signed_certificate() {
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
    ADMIN_CERT_FILE="$cert_dir/cert.der"
    ADMIN_KEY_FILE="$cert_dir/key.der"
}

pem_certificate_ready() {
    local cert="$1" key="$2" host="$3" minimum_seconds="${4:-172800}"
    [[ -s "$cert" && -s "$key" ]] || return 1
    openssl x509 -in "$cert" -checkend "$minimum_seconds" -noout >/dev/null 2>&1 || return 1
    openssl verify -purpose sslserver -verify_ip "$host" -untrusted "$cert" "$cert" >/dev/null 2>&1 || return 1
    cmp -s <(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null) \
        <(openssl pkey -in "$key" -passin pass: -pubout 2>/dev/null)
}

ensure_certbot() {
    local certbot_home="${OMEGA_CERTBOT_HOME:-/opt/omega/certbot}"
    CERTBOT_BIN="$certbot_home/bin/certbot"
    if [[ -x "$CERTBOT_BIN" ]] && "$CERTBOT_BIN" --version | python3 -c \
        'import re,sys; v=re.search(r"(\d+)\.(\d+)",sys.stdin.read()); sys.exit(0 if v and tuple(map(int,v.groups())) >= (5,4) else 1)'; then
        return 0
    fi
    python3 -m venv "$certbot_home"
    "$certbot_home/bin/python" -m pip install --disable-pip-version-check --upgrade 'certbot>=5.4,<6'
}

ensure_letsencrypt_certificate() {
    local cert_dir="$1" host="$2" acme_dir lineage stage
    install -d -m 0700 "$cert_dir"
    exec 9>"$cert_dir/renew.lock"
    flock -x 9
    CERT_RENEWED=0
    ADMIN_CERT_FILE="$cert_dir/fullchain.pem"
    ADMIN_KEY_FILE="$cert_dir/privkey.pem"
    if pem_certificate_ready "$ADMIN_CERT_FILE" "$ADMIN_KEY_FILE" "$host"; then
        flock -u 9
        exec 9>&-
        return 0
    fi
    ensure_certbot
    acme_dir="${OMEGA_ACME_STATE_DIR:-$(dirname "$cert_dir")/acme}"
    install -d -m 0700 "$acme_dir"
    local authenticator=(--standalone)
    if [[ -n "${OMEGA_ACME_WEBROOT:-}" ]]; then
        [[ "$OMEGA_ACME_WEBROOT" =~ ^/[A-Za-z0-9_./-]+$ ]] || fail "OMEGA_ACME_WEBROOT must be an absolute Linux path without spaces or shell metacharacters."
        authenticator=(--webroot --webroot-path "$OMEGA_ACME_WEBROOT")
    fi
    # HTTP-01 validation always needs inbound TCP 80, independently of the admin port.
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
        ufw allow 80/tcp >/dev/null
    fi
    if ! "$CERTBOT_BIN" certonly --non-interactive --agree-tos --register-unsafely-without-email \
        --server https://acme-v02.api.letsencrypt.org/directory \
        --required-profile shortlived --preferred-challenges http --ip-address "$host" \
        --cert-name omega-admin --keep-until-expiring "${authenticator[@]}" \
        --config-dir "$acme_dir/config" --work-dir "$acme_dir/work" --logs-dir "$acme_dir/logs"; then
        fail "Let's Encrypt issuance failed. Allow inbound TCP 80 in the VPS/provider firewall. If port 80 has a webserver, configure OMEGA_ACME_WEBROOT. Existing admin credentials were preserved."
    fi
    lineage="$acme_dir/config/live/omega-admin"
    pem_certificate_ready "$lineage/fullchain.pem" "$lineage/privkey.pem" "$host" 3600 || \
        fail "The issued certificate is not trusted, does not match the IP, or has an invalid private key."
    if ! cmp -s "$lineage/fullchain.pem" "$ADMIN_CERT_FILE" || ! cmp -s "$lineage/privkey.pem" "$ADMIN_KEY_FILE"; then
        stage="$(mktemp -d "$cert_dir/.trusted-XXXXXX")"
        install -m 0644 "$lineage/fullchain.pem" "$stage/fullchain.pem"
        install -m 0600 "$lineage/privkey.pem" "$stage/privkey.pem"
        mv -f -- "$stage/privkey.pem" "$ADMIN_KEY_FILE"
        mv -f -- "$stage/fullchain.pem" "$ADMIN_CERT_FILE"
        rmdir "$stage"
        CERT_RENEWED=1
    fi
    flock -u 9
    exec 9>&-
}

ensure_admin_certificate() {
    export OMEGA_ADMIN_TLS_MODE="${OMEGA_ADMIN_TLS_MODE:-letsencrypt}"
    case "$OMEGA_ADMIN_TLS_MODE" in
        letsencrypt) ensure_letsencrypt_certificate "$@" ;;
        self-signed) ensure_self_signed_certificate "$@" ;;
        *) fail "OMEGA_ADMIN_TLS_MODE must be letsencrypt or self-signed." ;;
    esac
}

configure_admin() {
    local config="$1" state_dir="$2" binary="$3" credentials_output="$4"
    local host port cert_dir url_host client_host
    host="$(detect_public_host)"
    port="${OMEGA_ADMIN_HTTPS_PORT:-8443}"
    [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || fail "Invalid HTTPS admin port."
    [[ "$port" != "${OMEGA_TCP_PORT:-443}" ]] || fail "HTTPS admin port conflicts with the VPN TCP port."
    cert_dir="$state_dir/admin-tls"
    export OMEGA_CERTBOT_HOME="${OMEGA_CERTBOT_HOME:-$(dirname "$state_dir")/certbot}"
    ensure_admin_certificate "$cert_dir" "$host"
    OMEGA_ADMIN_TLS_CERT="$ADMIN_CERT_FILE" OMEGA_ADMIN_TLS_KEY="$ADMIN_KEY_FILE" "$binary" admin check_web_tls
    export OMEGA_ADMIN_AUTH_DB="$state_dir/admin-auth.json"
    (umask 077; "$binary" admin init_web > "$credentials_output")
    set_config "$config" OMEGA_PUBLIC_HOST "$host"
    set_config "$config" OMEGA_ADMIN_AUTH_DB "$OMEGA_ADMIN_AUTH_DB"
    set_config "$config" OMEGA_ADMIN_TLS_CERT "$ADMIN_CERT_FILE"
    set_config "$config" OMEGA_ADMIN_TLS_KEY "$ADMIN_KEY_FILE"
    set_config "$config" OMEGA_ADMIN_TLS_MODE "$OMEGA_ADMIN_TLS_MODE"
    set_config "$config" OMEGA_ADMIN_TLS_HOT_RELOAD 1
    set_config "$config" OMEGA_CERTBOT_HOME "$OMEGA_CERTBOT_HOME"
    if [[ -n "${OMEGA_ACME_WEBROOT:-}" ]]; then set_config "$config" OMEGA_ACME_WEBROOT "$OMEGA_ACME_WEBROOT"; fi
    if [[ -n "${OMEGA_ACME_STATE_DIR:-}" ]]; then set_config "$config" OMEGA_ACME_STATE_DIR "$OMEGA_ACME_STATE_DIR"; fi
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
    local requested_public_host="${OMEGA_PUBLIC_HOST:-}" requested_admin_port="${OMEGA_ADMIN_HTTPS_PORT:-}" requested_tls_mode="${OMEGA_ADMIN_TLS_MODE:-}"
    local requested_webroot="${OMEGA_ACME_WEBROOT:-}"
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
    if [[ -n "$requested_tls_mode" ]]; then export OMEGA_ADMIN_TLS_MODE="$requested_tls_mode"; fi
    if [[ -n "$requested_webroot" ]]; then export OMEGA_ACME_WEBROOT="$requested_webroot"; fi
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
