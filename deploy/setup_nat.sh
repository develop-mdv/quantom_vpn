#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Omega VPN nftables bootstrap.

Usage:
  sudo OMEGA_VPN_PORT=443 bash setup_nat.sh [public_iface]

Environment:
  OMEGA_PUBLIC_IFACE           public interface; autodetected from default route when empty
  OMEGA_TUN_IFACE_PATTERN      tunnel interface glob for nftables (default: tun*)
  OMEGA_CLIENT_CIDR            VPN client subnet (default: 10.7.0.0/16)
  OMEGA_VPN_PORT               public UDP port (default: 443)
  OMEGA_VPN_PROTO              must stay udp for the current Omega datapath (default: udp)
  OMEGA_VPN_IPV6_MODE          disabled or exit with error (default: disabled)
  OMEGA_SSH_PORT               SSH port to preserve (default: 22)
  OMEGA_ADMIN_WEB_PUBLIC       1/0, expose built-in admin UI publicly (default: 0)
  OMEGA_ADMIN_WEB_PORT         built-in admin UI TCP port (default: 8081)
  OMEGA_METRICS_PUBLIC         1/0, expose Prometheus metrics publicly (default: 0)
  OMEGA_METRICS_PORT           Prometheus metrics TCP port (default: 9090)
  OMEGA_RMEM_MAX               net.core.rmem_max value (default: 8388608)
  OMEGA_WMEM_MAX               net.core.wmem_max value (default: 8388608)
  OMEGA_NETDEV_MAX_BACKLOG     net.core.netdev_max_backlog value (default: 4096)
  OMEGA_UDP_RMEM_MIN           net.ipv4.udp_rmem_min value (default: 262144)
  OMEGA_UDP_WMEM_MIN           net.ipv4.udp_wmem_min value (default: 262144)
  OMEGA_CONNTRACK_UDP_TIMEOUT  nf_conntrack UDP timeout seconds (default: 120)
  OMEGA_CONNTRACK_UDP_STREAM   nf_conntrack UDP stream timeout seconds (default: 180)
  OMEGA_NFT_TRACE              1/0, enable nftrace for VPN forward traffic (default: 0)
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "[ERROR] Run this script as root."
    exit 1
fi

IFACE="${OMEGA_PUBLIC_IFACE:-${1:-}}"
TUN_IFACE_PATTERN="${OMEGA_TUN_IFACE_PATTERN:-tun*}"
CLIENT_CIDR="${OMEGA_CLIENT_CIDR:-10.7.0.0/16}"
VPN_PORT="${OMEGA_VPN_PORT:-443}"
VPN_PROTO="${OMEGA_VPN_PROTO:-udp}"
VPN_IPV6_MODE="${OMEGA_VPN_IPV6_MODE:-disabled}"
SSH_PORT="${OMEGA_SSH_PORT:-22}"
ADMIN_WEB_PUBLIC="${OMEGA_ADMIN_WEB_PUBLIC:-0}"
ADMIN_WEB_PORT="${OMEGA_ADMIN_WEB_PORT:-8081}"
METRICS_PUBLIC="${OMEGA_METRICS_PUBLIC:-0}"
METRICS_PORT="${OMEGA_METRICS_PORT:-9090}"
RMEM_MAX="${OMEGA_RMEM_MAX:-8388608}"
WMEM_MAX="${OMEGA_WMEM_MAX:-8388608}"
NETDEV_MAX_BACKLOG="${OMEGA_NETDEV_MAX_BACKLOG:-4096}"
UDP_RMEM_MIN="${OMEGA_UDP_RMEM_MIN:-262144}"
UDP_WMEM_MIN="${OMEGA_UDP_WMEM_MIN:-262144}"
CONNTRACK_UDP_TIMEOUT="${OMEGA_CONNTRACK_UDP_TIMEOUT:-120}"
CONNTRACK_UDP_STREAM="${OMEGA_CONNTRACK_UDP_STREAM:-180}"
NFT_TRACE="${OMEGA_NFT_TRACE:-0}"

SYSCTL_FILE="/etc/sysctl.d/99-omega.conf"
NFT_DIR="/etc/nftables.d"
NFT_CONF="${NFT_DIR}/omega-vpn.nft"
NFT_MAIN="/etc/nftables.conf"
NFT_INET_TABLE="omega_vpn"
NFT_NAT_TABLE="omega_vpn_nat"

if [[ -z "$IFACE" ]]; then
    IFACE="$(ip -o route show to default 2>/dev/null | awk 'NR == 1 { print $5 }')"
fi

if [[ -z "$IFACE" ]]; then
    echo "[ERROR] Could not detect public interface. Set OMEGA_PUBLIC_IFACE or pass it explicitly."
    exit 1
fi

require_numeric() {
    local value="$1"
    local label="$2"
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "[ERROR] ${label} must be numeric."
        exit 1
    fi
}

for pair in \
    "$VPN_PORT OMEGA_VPN_PORT" \
    "$SSH_PORT OMEGA_SSH_PORT" \
    "$ADMIN_WEB_PORT OMEGA_ADMIN_WEB_PORT" \
    "$METRICS_PORT OMEGA_METRICS_PORT" \
    "$RMEM_MAX OMEGA_RMEM_MAX" \
    "$WMEM_MAX OMEGA_WMEM_MAX" \
    "$NETDEV_MAX_BACKLOG OMEGA_NETDEV_MAX_BACKLOG" \
    "$UDP_RMEM_MIN OMEGA_UDP_RMEM_MIN" \
    "$UDP_WMEM_MIN OMEGA_UDP_WMEM_MIN" \
    "$CONNTRACK_UDP_TIMEOUT OMEGA_CONNTRACK_UDP_TIMEOUT" \
    "$CONNTRACK_UDP_STREAM OMEGA_CONNTRACK_UDP_STREAM"; do
    require_numeric "${pair%% *}" "${pair#* }"
done

if [[ "$VPN_PROTO" != "udp" ]]; then
    echo "[ERROR] The current Omega datapath is UDP-only; do not bootstrap a TCP gaming profile here."
    exit 1
fi

if [[ "$VPN_IPV6_MODE" != "disabled" ]]; then
    echo "[ERROR] Current Omega tunnel is IPv4-only. Set OMEGA_VPN_IPV6_MODE=disabled."
    exit 1
fi

for tool in nft sysctl ip awk; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[ERROR] Required tool '$tool' is not installed."
        exit 1
    fi
done

persist_sysctl() {
    local key="$1"
    local value="$2"
    local escaped_key="${key//./\\.}"

    mkdir -p "$(dirname "$SYSCTL_FILE")"
    touch "$SYSCTL_FILE"

    if grep -Eq "^${escaped_key}=" "$SYSCTL_FILE"; then
        sed -i "s/^${escaped_key}=.*/${key}=${value}/" "$SYSCTL_FILE"
    else
        printf '%s=%s\n' "$key" "$value" >> "$SYSCTL_FILE"
    fi

    sysctl -q -w "${key}=${value}" >/dev/null 2>&1 || true
}

ensure_nft_include() {
    mkdir -p "$NFT_DIR"
    if [[ ! -f "$NFT_MAIN" ]]; then
        # Do NOT use "flush ruleset" here — it destroys rules from Docker,
        # hosting panels, and other services that use iptables-nft or nftables.
        # Omega tables are self-contained: each .nft file deletes and recreates
        # only its own tables, leaving everything else untouched.
        cat >"$NFT_MAIN" <<'EOF'
#!/usr/sbin/nft -f
include "/etc/nftables.d/*.nft"
EOF
        return
    fi

    # If the existing nftables.conf has "flush ruleset", remove it to prevent
    # wiping out Docker / hosting-panel / provider firewall rules on restart.
    if grep -Fq 'flush ruleset' "$NFT_MAIN"; then
        sed -i '/^[[:space:]]*flush ruleset/d' "$NFT_MAIN"
        echo "[INFO] Removed 'flush ruleset' from $NFT_MAIN to preserve other services' rules"
    fi

    if ! grep -Fq 'include "/etc/nftables.d/*.nft"' "$NFT_MAIN"; then
        printf '\ninclude "/etc/nftables.d/*.nft"\n' >> "$NFT_MAIN"
    fi
}

render_nft_config() {
    local vpn_input_rule
    local admin_rule=""
    local metrics_rule=""
    local trace_rule=""

    vpn_input_rule="udp dport ${VPN_PORT} counter accept"
    if [[ "$ADMIN_WEB_PUBLIC" == "1" ]]; then
        admin_rule="tcp dport ${ADMIN_WEB_PORT} counter accept"
    fi
    if [[ "$METRICS_PUBLIC" == "1" ]]; then
        metrics_rule="tcp dport ${METRICS_PORT} counter accept"
    fi
    if [[ "$NFT_TRACE" == "1" ]]; then
        trace_rule="iifname \"${TUN_IFACE_PATTERN}\" meta nftrace set 1"
    fi

    cat >"$NFT_CONF" <<EOF
# Omega VPN nftables rules.
# This file only manages Omega-specific tables and never touches rules
# owned by Docker, hosting panels, or other services.
#
# Tables are pre-deleted before loading (see setup_nat.sh), so this file
# only contains the table definitions — safe to include at boot time
# even if the tables don't exist yet.

table inet ${NFT_INET_TABLE} {
    chain input {
        type filter hook input priority filter; policy accept;
        ct state invalid counter drop
        iifname "lo" accept
        ct state established,related accept
        tcp dport ${SSH_PORT} counter accept
        ${vpn_input_rule}
        ${admin_rule}
        ${metrics_rule}
    }

    chain mss_clamp {
        type filter hook forward priority mangle; policy accept;
        oifname "${IFACE}" ip saddr ${CLIENT_CIDR} tcp flags syn / syn,rst tcp option maxseg size set rt mtu
    }

    chain forward {
        type filter hook forward priority filter; policy accept;
        ct state invalid counter drop
        ct state established,related counter accept
        ${trace_rule}
        iifname "${TUN_IFACE_PATTERN}" oifname "${IFACE}" ip saddr ${CLIENT_CIDR} counter accept
        iifname "${IFACE}" oifname "${TUN_IFACE_PATTERN}" ip daddr ${CLIENT_CIDR} ct state established,related counter accept
        iifname "${TUN_IFACE_PATTERN}" counter log prefix "omega-forward-drop: " drop
        oifname "${TUN_IFACE_PATTERN}" counter log prefix "omega-forward-drop: " drop
    }
}

table ip ${NFT_NAT_TABLE} {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr ${CLIENT_CIDR} oifname "${IFACE}" counter masquerade
    }
}
EOF
}

echo "[INFO] Public interface: ${IFACE}"
echo "[INFO] Tunnel interface pattern: ${TUN_IFACE_PATTERN}"
echo "[INFO] VPN client subnet: ${CLIENT_CIDR}"
echo "[INFO] VPN transport: ${VPN_PROTO}/${VPN_PORT}"
echo "[INFO] IPv6 mode: ${VPN_IPV6_MODE} (explicitly disabled for the current IPv4-only Omega tunnel)"

echo "[INFO] Applying sysctl tuning for UDP-first VPN traffic..."
persist_sysctl "net.ipv4.ip_forward" "1"
persist_sysctl "net.ipv6.conf.all.forwarding" "0"
persist_sysctl "net.ipv4.conf.all.rp_filter" "2"
persist_sysctl "net.ipv4.conf.default.rp_filter" "2"
persist_sysctl "net.ipv4.conf.${IFACE}.rp_filter" "2"
persist_sysctl "net.ipv4.tcp_mtu_probing" "1"
persist_sysctl "net.core.rmem_max" "$RMEM_MAX"
persist_sysctl "net.core.wmem_max" "$WMEM_MAX"
persist_sysctl "net.core.netdev_max_backlog" "$NETDEV_MAX_BACKLOG"
persist_sysctl "net.ipv4.udp_rmem_min" "$UDP_RMEM_MIN"
persist_sysctl "net.ipv4.udp_wmem_min" "$UDP_WMEM_MIN"
persist_sysctl "net.netfilter.nf_conntrack_udp_timeout" "$CONNTRACK_UDP_TIMEOUT"
persist_sysctl "net.netfilter.nf_conntrack_udp_timeout_stream" "$CONNTRACK_UDP_STREAM"

echo "[INFO] Writing nftables rules to ${NFT_CONF}"
ensure_nft_include
render_nft_config

# Delete existing Omega tables before loading (ignore errors on first run
# when tables don't exist yet). Only Omega's own tables are touched —
# Docker, hosting panel, and provider rules remain intact.
nft delete table inet "$NFT_INET_TABLE" >/dev/null 2>&1 || true
nft delete table ip "$NFT_NAT_TABLE" >/dev/null 2>&1 || true
nft -f "$NFT_CONF"

# Enable nftables for boot persistence, but do NOT restart the service.
# The nft -f command above already applied the rules atomically.
# Restarting nftables would re-run /etc/nftables.conf, which on many systems
# contains "flush ruleset" that destroys Docker, hosting panel, and provider
# firewall rules — causing admin panels and other services to break.
if systemctl list-unit-files nftables.service >/dev/null 2>&1; then
    systemctl enable nftables >/dev/null 2>&1 || true
fi

echo
echo "[INFO] Applied ruleset:"
nft list table inet "$NFT_INET_TABLE"
echo
nft list table ip "$NFT_NAT_TABLE"

echo
echo "[INFO] Steam/Dota readiness notes:"
echo "  - No selective egress filtering is applied to Steam UDP ports 3478, 4379, 4380, 27000-27250."
echo "  - MASQUERADE is enabled for ${CLIENT_CIDR} -> ${IFACE}."
echo "  - MSS clamping follows path MTU on the VPN forward path."
echo "  - rp_filter is forced to loose mode (2) to avoid asymmetric-route drops."
echo "  - nf_conntrack UDP timeouts were raised to ${CONNTRACK_UDP_TIMEOUT}/${CONNTRACK_UDP_STREAM} seconds."

echo
echo "[INFO] Next steps:"
echo "  1. Keep cloud security groups outbound-open for UDP."
echo "  2. Keep the client gaming profile on UDP only."
echo "  3. Use deploy/diagnose_server.sh after the service is up."
