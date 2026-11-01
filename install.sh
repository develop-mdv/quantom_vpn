#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="develop-mdv/quantom_vpn"

usage() {
    cat <<'EOF'
Omega VPN server installer (Debian 12+ / Ubuntu 22.04+, systemd).

Run as root:
  bash install.sh             Install the latest GitHub release
  bash install.sh v0.1.0      Install a specific release

Optional environment:
  OMEGA_SSH_PORT             SSH port to preserve (auto-detected, otherwise 22)
  OMEGA_PUBLIC_IFACE         Public interface (otherwise auto-detected)
  OMEGA_VPN_IPV6_MODE        disabled (default) or nat66

Installs to /opt/omega, preserves /opt/omega/state and existing settings in
/etc/default/omega-server. The admin UI is available through an SSH tunnel.
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
apt-get install -y ca-certificates curl tar coreutils iproute2 nftables kmod

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
for file in omega-server omega-server.service setup_nat.sh update_server.sh diagnose_server.sh; do
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
set -a
# shellcheck source=/dev/null
source /etc/default/omega-server
set +a
export OMEGA_VPN_IPV6_MODE="${OMEGA_IPV6_MODE:-disabled}"
SSH_CONNECTION_VALUE="${SSH_CONNECTION:-}"
export OMEGA_SSH_PORT="${OMEGA_SSH_PORT:-${SSH_CONNECTION_VALUE##* }}"
export OMEGA_SSH_PORT="${OMEGA_SSH_PORT:-22}"
export OMEGA_RELEASE_ID="$VERSION-$(date +%Y%m%d%H%M%S)"
export OMEGA_DEPLOY_HEALTHCHECK=0

bash "$TEMP_DIR/setup_nat.sh"
bash "$TEMP_DIR/update_server.sh" "$TEMP_DIR/omega-server" "$TEMP_DIR/omega-server.service"
systemctl enable omega-server
install -m 0755 "$TEMP_DIR/diagnose_server.sh" /opt/omega/diagnose_server.sh

echo "[INFO] Omega VPN $VERSION installed."
echo "[INFO] Settings: /etc/default/omega-server; state: /opt/omega/state"
echo "[INFO] Logs: journalctl -u omega-server -f"
echo "[INFO] Open the admin UI through an SSH tunnel from your PC:"
echo "       ssh -N -L 8081:127.0.0.1:8081 -p $OMEGA_SSH_PORT root@<server_ip>"
echo "       Then open http://127.0.0.1:8081 and create a user/device."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
