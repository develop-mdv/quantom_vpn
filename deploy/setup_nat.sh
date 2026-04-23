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
  OMEGA_CLIENT_CIDR_V6         VPN client IPv6 prefix (default: fd70:7::/64)
  OMEGA_VPN_PORT               public UDP port (default: 443)
  OMEGA_VPN_PROTO              must stay udp for the current Omega datapath (default: udp)
  OMEGA_VPN_IPV6_MODE          disabled or nat66 (default: disabled)
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
CLIENT_CIDR_V6="${OMEGA_CLIENT_CIDR_V6:-fd70:7::/64}"
VPN_PORT="${OMEGA_VPN_PORT:-443}"
VPN_PROTO="${OMEGA_VPN_PROTO:-udp}"
VPN_IPV6_MODE="${OMEGA_VPN_IPV6_MODE:-${OMEGA_IPV6_MODE:-disabled}}"
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
NFT_NAT6_TABLE="omega_vpn_nat6"

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

if [[ "$VPN_IPV6_MODE" != "disabled" && "$VPN_IPV6_MODE" != "nat66" ]]; then
    echo "[ERROR] OMEGA_VPN_IPV6_MODE must be disabled or nat66."
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
        cat >"$NFT_MAIN" <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables.d/*.nft"
EOF
        return
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
    local ipv6_mss_rule=""
    local ipv6_forward_rules=""
    local nat6_table=""

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
    if [[ "$VPN_IPV6_MODE" == "nat66" ]]; then
        ipv6_mss_rule="        oifname \"${IFACE}\" ip6 saddr ${CLIENT_CIDR_V6} tcp flags syn / syn,rst tcp option maxseg size set rt mtu"
        ipv6_forward_rules=$'        iifname "'"${TUN_IFACE_PATTERN}"'" oifname "'"${IFACE}"'" ip6 saddr '"${CLIENT_CIDR_V6}"' counter accept\n        iifname "'"${IFACE}"'" oifname "'"${TUN_IFACE_PATTERN}"'" ip6 daddr '"${CLIENT_CIDR_V6}"' ct state established,related counter accept'
        nat6_table=$(cat <<EOF
table ip6 ${NFT_NAT6_TABLE} {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip6 saddr ${CLIENT_CIDR_V6} oifname "${IFACE}" counter masquerade
    }
}
EOF
)
    fi

    cat >"$NFT_CONF" <<EOF
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
${ipv6_mss_rule}
    }

    chain forward {
        type filter hook forward priority filter; policy accept;
        ct state invalid counter drop
        ct state established,related counter accept
        ${trace_rule}
        iifname "${TUN_IFACE_PATTERN}" oifname "${IFACE}" ip saddr ${CLIENT_CIDR} counter accept
        iifname "${IFACE}" oifname "${TUN_IFACE_PATTERN}" ip daddr ${CLIENT_CIDR} ct state established,related counter accept
${ipv6_forward_rules}
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
    if [[ -n "$nat6_table" ]]; then
        printf '\n%s\n' "$nat6_table" >> "$NFT_CONF"
    fi
}

echo "[INFO] Public interface: ${IFACE}"
echo "[INFO] Tunnel interface pattern: ${TUN_IFACE_PATTERN}"
echo "[INFO] VPN client subnet: ${CLIENT_CIDR}"
echo "[INFO] VPN client IPv6 prefix: ${CLIENT_CIDR_V6}"
echo "[INFO] VPN transport: ${VPN_PROTO}/${VPN_PORT}"
echo "[INFO] IPv6 mode: ${VPN_IPV6_MODE}"

echo "[INFO] Applying sysctl tuning for UDP-first VPN traffic..."
persist_sysctl "net.ipv4.ip_forward" "1"
if [[ "$VPN_IPV6_MODE" == "nat66" ]]; then
    persist_sysctl "net.ipv6.conf.all.forwarding" "1"
else
    persist_sysctl "net.ipv6.conf.all.forwarding" "0"
fi
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

nft delete table inet "$NFT_INET_TABLE" >/dev/null 2>&1 || true
nft delete table ip "$NFT_NAT_TABLE" >/dev/null 2>&1 || true
nft delete table ip6 "$NFT_NAT6_TABLE" >/dev/null 2>&1 || true
nft -f "$NFT_CONF"

if systemctl list-unit-files nftables.service >/dev/null 2>&1; then
    systemctl enable nftables >/dev/null 2>&1 || true
    systemctl restart nftables >/dev/null 2>&1 || true
fi

echo
echo "[INFO] Applied ruleset:"
nft list table inet "$NFT_INET_TABLE"
echo
nft list table ip "$NFT_NAT_TABLE"
if [[ "$VPN_IPV6_MODE" == "nat66" ]]; then
    echo
    nft list table ip6 "$NFT_NAT6_TABLE"
fi

echo
echo "[INFO] Steam/Dota readiness notes:"
echo "  - No selective egress filtering is applied to Steam UDP ports 3478, 4379, 4380, 27000-27250."
echo "  - MASQUERADE is enabled for ${CLIENT_CIDR} -> ${IFACE}."
if [[ "$VPN_IPV6_MODE" == "nat66" ]]; then
    echo "  - NAT66 is enabled for ${CLIENT_CIDR_V6} -> ${IFACE}."
fi
echo "  - MSS clamping follows path MTU on the VPN forward path."
echo "  - rp_filter is forced to loose mode (2) to avoid asymmetric-route drops."
echo "  - nf_conntrack UDP timeouts were raised to ${CONNTRACK_UDP_TIMEOUT}/${CONNTRACK_UDP_STREAM} seconds."

echo
echo "[INFO] Next steps:"
echo "  1. Keep cloud security groups outbound-open for UDP."
echo "  2. Keep the client gaming profile on UDP only, even when inner IPv6 is enabled."
echo "  3. Use deploy/diagnose_server.sh after the service is up."
