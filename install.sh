#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="develop-mdv/quantom_vpn"

usage() {
    cat <<'EOF'
Omega VPN server installer (Debian 12+ / Ubuntu 22.04+, systemd).

Run as root:
  bash install.sh             Install the latest GitHub release
  bash install.sh v0.1.0      Install a specific release (updated v0.1.0 or newer)

Optional environment:
  OMEGA_SSH_PORT             SSH port to preserve (auto-detected, otherwise 22)
  OMEGA_PUBLIC_IFACE         Public interface (otherwise auto-detected)
  OMEGA_VPN_IPV6_MODE        disabled (default) or nat66
  OMEGA_PUBLIC_HOST          Public server IP (otherwise detected)
  OMEGA_ADMIN_HTTPS_PORT     Public HTTPS admin port (default: 8443)

Installs to /opt/omega, preserves /opt/omega/state and existing settings in
/etc/default/omega-server. Prints the HTTPS URL and generated admin credentials.
EOF
}

fail() { echo "[ERROR] $*" >&2; exit 1; }

verify_download() {
    local directory="$1" asset="$2"
    (
        cd "$directory"
        awk -v asset="$asset" '{ name = $2; sub(/^\*/, "", name); if (name == asset) print }' SHA256SUMS > checksum
        [[ "$(wc -l < checksum)" -eq 1 ]] || fail "Missing or duplicate checksum for $asset."
        sha256sum --check --strict checksum
    )
}

write_default_config() {
    local config="$1"
    [[ ! -e "$config" ]] || return 0
    cat > "$config" <<EOF
OMEGA_BIND=[::]:443
OMEGA_TCP_ENABLE=1
OMEGA_TCP_BIND=[::]:443
OMEGA_VPN_PORT=443
OMEGA_TCP_PORT=443
OMEGA_IPV6_MODE=${OMEGA_VPN_IPV6_MODE:-disabled}
OMEGA_ADMIN_WEB_BIND=127.0.0.1:8081
OMEGA_ADMIN_WEB_PUBLIC=0
OMEGA_ADMIN_WEB_PORT=8081
OMEGA_METRICS_BIND=127.0.0.1:9090
OMEGA_METRICS_PUBLIC=0
OMEGA_METRICS_PORT=9090
EOF
    chmod 0600 "$config"
}


main() {
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi
[[ $# -le 1 ]] || fail "Expected at most one release tag. See --help."
VERSION="${1:-latest}"
[[ "$VERSION" == "latest" || "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Expected a tag such as v0.1.0."
[[ "$(uname -s)" == "Linux" ]] || fail "This installer requires Linux."
[[ "$(id -u)" == "0" ]] || fail "Run as root (sudo -i)."
[[ -d /run/systemd/system ]] || fail "A running systemd system is required."
command -v apt-get >/dev/null || fail "This installer supports Debian/Ubuntu with apt-get."
case "$(uname -m)" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) fail "Unsupported CPU architecture: $(uname -m)" ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl tar coreutils iproute2 nftables kmod openssl python3 util-linux

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEMP_DIR"' EXIT
if [[ "$VERSION" == "latest" ]]; then
    RELEASE_URL="$(curl --fail --silent --show-error --location --retry 3 \
        --output /dev/null --write-out '%{url_effective}' \
        "https://github.com/$REPOSITORY/releases/latest")"
    VERSION="${RELEASE_URL##*/}"
    [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "No published release found. Pass a version tag explicitly."
fi

ASSET="omega-server-linux-$ARCH.tar.gz"
BASE_URL="https://github.com/$REPOSITORY/releases/download/$VERSION"
echo "[INFO] Downloading $VERSION ($ARCH)"
curl --fail --silent --show-error --location --retry 3 "$BASE_URL/$ASSET" --output "$TEMP_DIR/$ASSET"
curl --fail --silent --show-error --location --retry 3 "$BASE_URL/SHA256SUMS" --output "$TEMP_DIR/SHA256SUMS"
verify_download "$TEMP_DIR" "$ASSET"
tar -xzf "$TEMP_DIR/$ASSET" -C "$TEMP_DIR"
for file in omega-server omega-server.service setup_nat.sh update_server.sh diagnose_server.sh setup_admin.sh renew_admin_tls.sh omega-admin-tls-renew.service omega-admin-tls-renew.timer; do
    [[ -f "$TEMP_DIR/$file" ]] || fail "Incomplete release bundle: $file is missing."
done
chmod +x "$TEMP_DIR/omega-server" "$TEMP_DIR/"*.sh

[[ -c /dev/net/tun ]] || modprobe tun
[[ -c /dev/net/tun ]] || fail "/dev/net/tun is unavailable. Enable TUN on the VPS."
install -d -m 0700 /opt/omega/state
install -d -m 0755 /etc/default

# Reinstalling/upgrading must keep the settings and device credentials.
write_default_config /etc/default/omega-server

# The installer creates shell-compatible KEY=value settings. Existing files
# must use the same format if they are also used for network setup below.
requested_public_host="${OMEGA_PUBLIC_HOST:-}"
requested_admin_port="${OMEGA_ADMIN_HTTPS_PORT:-}"
set -a
# shellcheck source=/dev/null
source /etc/default/omega-server
set +a
if [[ -n "$requested_public_host" ]]; then export OMEGA_PUBLIC_HOST="$requested_public_host"; fi
if [[ -n "$requested_admin_port" ]]; then export OMEGA_ADMIN_HTTPS_PORT="$requested_admin_port"; fi
export OMEGA_VPN_IPV6_MODE="${OMEGA_IPV6_MODE:-disabled}"
SSH_CONNECTION_VALUE="${SSH_CONNECTION:-}"
export OMEGA_SSH_PORT="${OMEGA_SSH_PORT:-${SSH_CONNECTION_VALUE##* }}"
export OMEGA_SSH_PORT="${OMEGA_SSH_PORT:-22}"
export OMEGA_RELEASE_ID="$VERSION-$(date +%Y%m%d%H%M%S)"
export OMEGA_DEPLOY_HEALTHCHECK=0

source "$TEMP_DIR/setup_admin.sh"
configure_admin /etc/default/omega-server /opt/omega/state "$TEMP_DIR/omega-server" "$TEMP_DIR/admin-credentials.json"
if [[ -f /opt/omega/state/admin-bootstrap.json ]]; then
    python3 - "$TEMP_DIR/admin-credentials.json" /opt/omega/state/admin-bootstrap.json <<'PY'
import json, pathlib, sys
output, bootstrap = map(pathlib.Path, sys.argv[1:])
current, initial = json.loads(output.read_text()), json.loads(bootstrap.read_text())
if not current['created'] and initial.get('created') and current['login'] == initial['login']:
    output.write_text(json.dumps(initial))
PY
fi
bash "$TEMP_DIR/setup_nat.sh"
bash "$TEMP_DIR/update_server.sh" "$TEMP_DIR/omega-server" "$TEMP_DIR/omega-server.service"
systemctl enable omega-server
install -m 0755 "$TEMP_DIR/diagnose_server.sh" /opt/omega/diagnose_server.sh
openssl x509 -inform DER -in /opt/omega/state/admin-tls/cert.der -out "$TEMP_DIR/admin-cert.pem"
curl --fail --silent --show-error --noproxy '*' --retry 5 --retry-connrefused --retry-delay 1 \
    --connect-timeout 3 --max-time 15 --cacert "$TEMP_DIR/admin-cert.pem" \
    --connect-to "${ADMIN_URL#https://}:127.0.0.1:$OMEGA_ADMIN_WEB_PORT" \
    "$ADMIN_URL/login" --output /dev/null

echo "[INFO] Omega VPN $VERSION installed."
echo "[INFO] Settings: /etc/default/omega-server; state: /opt/omega/state"
echo "[INFO] Logs: journalctl -u omega-server -f"
echo ""
echo "Admin URL: $ADMIN_URL"
python3 - "$TEMP_DIR/admin-credentials.json" <<'PY'
import json, sys
credentials = json.load(open(sys.argv[1], encoding='utf-8'))
print('Login: ' + credentials['login'])
if credentials['created']:
    print('Password: ' + credentials['password'])
    print('Save this password. You can change login/password in the admin UI.')
else:
    print('Password: preserved (use your existing password).')
PY
rm -f -- /opt/omega/state/admin-bootstrap.json
echo "Certificate SHA-256 fingerprint:"
openssl x509 -inform DER -in /opt/omega/state/admin-tls/cert.der -noout -fingerprint -sha256
echo "The certificate is self-signed. Confirm it in your browser on first visit."
echo "Allow TCP $OMEGA_ADMIN_WEB_PORT in the VPS provider firewall."
echo "Reset access if needed: cd /opt/omega && ./omega-server admin reset_web && systemctl restart omega-server"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
