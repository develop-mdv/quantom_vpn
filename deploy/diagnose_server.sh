#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Omega VPN nftables diagnostics.

Usage:
  sudo bash diagnose_server.sh [public_iface]

Environment:
  OMEGA_PUBLIC_IFACE           public interface; autodetected from default route when empty
  OMEGA_TUN_IFACE_PATTERN      tunnel interface glob expected in nftables (default: tun*)
  OMEGA_CLIENT_CIDR            VPN client subnet (default: 10.7.0.0/16)
  OMEGA_CLIENT_CIDR_V6         VPN client IPv6 prefix (default: fd70:7::/64)
  OMEGA_VPN_PORT               public UDP port (default: 443)
  OMEGA_VPN_PROTO              expected primary transport, should stay udp (default: udp)
  OMEGA_TCP_ENABLE             1/0, expect framed TCP fallback listener (default: 1)
  OMEGA_TCP_PORT               framed TCP fallback port (default: OMEGA_VPN_PORT)
  OMEGA_VPN_IPV6_MODE          expected IPv6 mode: disabled or nat66 (default: disabled)
  OMEGA_SSH_PORT               SSH port that must remain reachable (default: 22)
  OMEGA_ADMIN_WEB_PUBLIC       1/0, expect public admin web UI (default: 0)
  OMEGA_ADMIN_WEB_PORT         admin web UI TCP port (default: 8081)
  OMEGA_METRICS_PUBLIC         1/0, expect public Prometheus metrics (default: 0)
  OMEGA_METRICS_PORT           Prometheus metrics TCP port (default: 9090)
  OMEGA_SERVICE_NAME           systemd service name (default: omega-server)
  OMEGA_RUNTIME_SNAPSHOT       runtime snapshot path (default: /opt/omega/state/runtime.json)
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

IFACE="${OMEGA_PUBLIC_IFACE:-${1:-}}"
TUN_IFACE_PATTERN="${OMEGA_TUN_IFACE_PATTERN:-tun*}"
CLIENT_CIDR="${OMEGA_CLIENT_CIDR:-10.7.0.0/16}"
CLIENT_CIDR_V6="${OMEGA_CLIENT_CIDR_V6:-fd70:7::/64}"
VPN_PORT="${OMEGA_VPN_PORT:-443}"
VPN_PROTO="${OMEGA_VPN_PROTO:-udp}"
TCP_ENABLE="${OMEGA_TCP_ENABLE:-1}"
TCP_PORT="${OMEGA_TCP_PORT:-$VPN_PORT}"
VPN_IPV6_MODE="${OMEGA_VPN_IPV6_MODE:-${OMEGA_IPV6_MODE:-disabled}}"
SSH_PORT="${OMEGA_SSH_PORT:-22}"
ADMIN_WEB_PUBLIC="${OMEGA_ADMIN_WEB_PUBLIC:-0}"
ADMIN_WEB_PORT="${OMEGA_ADMIN_WEB_PORT:-8081}"
METRICS_PUBLIC="${OMEGA_METRICS_PUBLIC:-0}"
METRICS_PORT="${OMEGA_METRICS_PORT:-9090}"
SERVICE_NAME="${OMEGA_SERVICE_NAME:-omega-server}"
RUNTIME_SNAPSHOT="${OMEGA_RUNTIME_SNAPSHOT:-/opt/omega/state/runtime.json}"
NFT_INET_TABLE="omega_vpn"
NFT_NAT_TABLE="omega_vpn_nat"
NFT_NAT6_TABLE="omega_vpn_nat6"
NFT_CONF="${OMEGA_NFT_CONF:-/etc/nftables.d/omega-vpn.nft}"
IPV6_EGRESS_TARGET="${OMEGA_IPV6_EGRESS_TARGET:-2606:4700:4700::1111}"

if [[ -z "$IFACE" ]]; then
    IFACE="$(ip -o route show to default 2>/dev/null | awk 'NR == 1 { print $5 }')"
fi

pass_count=0
warn_count=0
fail_count=0

pass() {
    pass_count=$((pass_count + 1))
    echo "[PASS] $*"
}

warn() {
    warn_count=$((warn_count + 1))
    echo "[WARN] $*"
}

fail() {
    fail_count=$((fail_count + 1))
    echo "[FAIL] $*"
}

cmd_exists() {
    command -v "$1" >/dev/null 2>&1
}

is_enabled() {
    case "${1,,}" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

if [[ -z "$IFACE" ]]; then
    fail "Could not detect the public interface."
fi

echo "[INFO] Public interface: ${IFACE:-unknown}"
echo "[INFO] Tunnel interface pattern: ${TUN_IFACE_PATTERN}"
echo "[INFO] Client subnet: ${CLIENT_CIDR}"
echo "[INFO] Client IPv6 prefix: ${CLIENT_CIDR_V6}"
echo "[INFO] VPN transport: ${VPN_PROTO}/${VPN_PORT}"
echo "[INFO] TCP fallback: ${TCP_ENABLE}/${TCP_PORT}"
echo "[INFO] IPv6 mode: ${VPN_IPV6_MODE}"
echo "[INFO] Runtime snapshot: ${RUNTIME_SNAPSHOT}"
echo

if [[ "$(id -u)" -ne 0 ]]; then
    warn "Running without root; nftables and conntrack checks may be incomplete."
fi

if [[ "$VPN_PROTO" == "udp" ]]; then
    pass "VPN transport is UDP-first as required for the current gaming profile."
else
    fail "Expected UDP transport, got ${VPN_PROTO}."
fi

case "$VPN_IPV6_MODE" in
    disabled)
        pass "IPv6 mode is disabled."
        ;;
    nat66)
        pass "IPv6 mode is nat66; dual-stack tunneling is expected."
        ;;
    *)
        fail "Unsupported IPv6 mode ${VPN_IPV6_MODE}."
        ;;
esac

if cmd_exists sysctl; then
    [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" == "1" ]] \
        && pass "IPv4 forwarding is enabled." \
        || fail "IPv4 forwarding is disabled."

    ipv6_forward="$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo 0)"
    if [[ "$VPN_IPV6_MODE" == "nat66" ]]; then
        [[ "$ipv6_forward" == "1" ]] \
            && pass "IPv6 forwarding is enabled." \
            || fail "IPv6 forwarding is disabled."
    else
        [[ "$ipv6_forward" == "0" ]] \
            && pass "IPv6 forwarding is disabled as expected." \
            || warn "IPv6 forwarding is enabled while OMEGA_VPN_IPV6_MODE=${VPN_IPV6_MODE}."
    fi

    [[ "$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo 0)" == "2" ]] \
        && pass "net.ipv4.conf.all.rp_filter is in loose mode." \
        || fail "net.ipv4.conf.all.rp_filter is not 2."

    [[ "$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null || echo 0)" == "2" ]] \
        && pass "net.ipv4.conf.default.rp_filter is in loose mode." \
        || fail "net.ipv4.conf.default.rp_filter is not 2."

    if [[ -n "$IFACE" ]]; then
        iface_rpf="$(sysctl -n "net.ipv4.conf.${IFACE}.rp_filter" 2>/dev/null || echo 2)"
        [[ "$iface_rpf" == "2" ]] \
            && pass "net.ipv4.conf.${IFACE}.rp_filter is in loose mode." \
            || warn "net.ipv4.conf.${IFACE}.rp_filter is ${iface_rpf}, expected 2."
    fi

    [[ "$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null || echo 0)" == "1" ]] \
        && pass "TCP MTU probing is enabled." \
        || warn "TCP MTU probing is disabled."

    udp_timeout="$(sysctl -n net.netfilter.nf_conntrack_udp_timeout 2>/dev/null || echo 0)"
    udp_stream="$(sysctl -n net.netfilter.nf_conntrack_udp_timeout_stream 2>/dev/null || echo 0)"
    if (( udp_timeout >= 60 )); then
        pass "nf_conntrack UDP timeout is ${udp_timeout}s."
    else
        warn "nf_conntrack UDP timeout is only ${udp_timeout}s."
    fi
    if (( udp_stream >= 120 )); then
        pass "nf_conntrack UDP stream timeout is ${udp_stream}s."
    else
        warn "nf_conntrack UDP stream timeout is only ${udp_stream}s."
    fi
else
    fail "sysctl is not available."
fi

if cmd_exists nft; then
    inet_table="$(nft list table inet "$NFT_INET_TABLE" 2>/dev/null || true)"
    nat_table="$(nft list table ip "$NFT_NAT_TABLE" 2>/dev/null || true)"
    nat6_table="$(nft list table ip6 "$NFT_NAT6_TABLE" 2>/dev/null || true)"

    if [[ -f "$NFT_CONF" ]]; then
        if nft -c -f "$NFT_CONF" >/dev/null 2>&1; then
            pass "Persisted nftables config validates cleanly."
        else
            fail "Persisted nftables config ${NFT_CONF} is invalid."
        fi
    else
        warn "Persisted nftables config ${NFT_CONF} is missing; live table checks continue."
    fi

    [[ -n "$inet_table" ]] \
        && pass "nftables inet table ${NFT_INET_TABLE} is loaded." \
        || fail "nftables inet table ${NFT_INET_TABLE} is missing."

    [[ -n "$nat_table" ]] \
        && pass "nftables nat table ${NFT_NAT_TABLE} is loaded." \
        || fail "nftables nat table ${NFT_NAT_TABLE} is missing."

    if grep -Fq 'tcp option maxseg size set rt mtu' <<<"$inet_table"; then
        pass "MSS clamping by PMTU is configured."
    else
        fail "MSS clamping rule is missing."
    fi

    if grep -Fq "ip saddr ${CLIENT_CIDR}" <<<"$inet_table"; then
        pass "Forward rule for ${CLIENT_CIDR} is present."
    else
        fail "Forward rule for ${CLIENT_CIDR} is missing."
    fi

    if grep -Fq "masquerade" <<<"$nat_table" && grep -Fq "ip saddr ${CLIENT_CIDR}" <<<"$nat_table"; then
        pass "MASQUERADE is enabled for ${CLIENT_CIDR}."
    else
        fail "MASQUERADE rule for ${CLIENT_CIDR} is missing."
    fi

    if [[ "$VPN_IPV6_MODE" == "nat66" ]]; then
        if grep -Fq "ip6 saddr ${CLIENT_CIDR_V6}" <<<"$inet_table"; then
            pass "IPv6 forward rule for ${CLIENT_CIDR_V6} is present."
        else
            fail "IPv6 forward rule for ${CLIENT_CIDR_V6} is missing."
        fi

        [[ -n "$nat6_table" ]] \
            && pass "nftables nat6 table ${NFT_NAT6_TABLE} is loaded." \
            || fail "nftables nat6 table ${NFT_NAT6_TABLE} is missing."

        if grep -Fq "masquerade" <<<"$nat6_table" && grep -Fq "ip6 saddr ${CLIENT_CIDR_V6}" <<<"$nat6_table"; then
            pass "NAT66 is enabled for ${CLIENT_CIDR_V6}."
        else
            fail "NAT66 rule for ${CLIENT_CIDR_V6} is missing."
        fi
    fi

    if is_enabled "$TCP_ENABLE"; then
        if grep -Fq "tcp dport ${TCP_PORT}" <<<"$inet_table"; then
            pass "TCP fallback input rule for ${TCP_PORT} is present."
        else
            fail "TCP fallback input rule for ${TCP_PORT} is missing."
        fi
    fi
else
    fail "nft is not installed."
fi

if systemctl is-active --quiet "$SERVICE_NAME"; then
    pass "systemd service ${SERVICE_NAME} is active."
else
    fail "systemd service ${SERVICE_NAME} is not active."
fi

if [[ "$VPN_IPV6_MODE" == "nat66" ]]; then
    if cmd_exists ip; then
        if ip -6 route get "$IPV6_EGRESS_TARGET" >/dev/null 2>&1; then
            pass "Server IPv6 route to ${IPV6_EGRESS_TARGET} is available."
        else
            fail "Server IPv6 route to ${IPV6_EGRESS_TARGET} is unavailable."
        fi
    else
        fail "ip tool is not available for IPv6 route validation."
    fi

    if cmd_exists ping; then
        if ping -6 -c 1 -W 3 "$IPV6_EGRESS_TARGET" >/dev/null 2>&1; then
            pass "Server IPv6 egress probe to ${IPV6_EGRESS_TARGET} passed."
        else
            fail "Server IPv6 egress probe to ${IPV6_EGRESS_TARGET} failed."
        fi
    else
        warn "ping is not available; IPv6 ICMP egress probe skipped."
    fi
fi

if cmd_exists ss; then
    if ss -H -lun 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${VPN_PORT}$"; then
        pass "UDP listener is present on port ${VPN_PORT}."
    else
        fail "UDP listener on port ${VPN_PORT} is not visible."
    fi

    if is_enabled "$TCP_ENABLE"; then
        if ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|\\[::\\]:|0\\.0\\.0\\.0:|\\*:)${TCP_PORT}$"; then
            pass "TCP fallback listener is present on port ${TCP_PORT}."
        else
            fail "TCP fallback listener on port ${TCP_PORT} is not visible."
        fi
    fi

    if is_enabled "$ADMIN_WEB_PUBLIC"; then
        if ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|\\[::\\]:|0\\.0\\.0\\.0:|\\*:)${ADMIN_WEB_PORT}$"; then
            pass "Admin web UI is exposed publicly on port ${ADMIN_WEB_PORT}."
        else
            fail "Admin web UI is expected to be public on ${ADMIN_WEB_PORT}, but no listener was found."
        fi
    else
        warn "Admin web public exposure is disabled by default; that is safer for production."
    fi

    if is_enabled "$METRICS_PUBLIC"; then
        if ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|\\[::\\]:|0\\.0\\.0\\.0:|\\*:)${METRICS_PORT}$"; then
            pass "Prometheus metrics are exposed publicly on port ${METRICS_PORT}."
        else
            fail "Metrics are expected to be public on ${METRICS_PORT}, but no listener was found."
        fi
    else
        warn "Prometheus metrics public exposure is disabled by default; that is safer for production."
    fi
else
    warn "ss is not installed; listener checks skipped."
fi

if [[ -f "$RUNTIME_SNAPSHOT" ]]; then
    pass "Runtime snapshot exists."
    if [[ "$VPN_IPV6_MODE" == "nat66" ]]; then
        if grep -Fq '"tunnel_family": "dual_stack"' "$RUNTIME_SNAPSHOT"; then
            pass "Runtime snapshot confirms dual-stack tunnel family."
        else
            fail "Runtime snapshot does not show tunnel_family=dual_stack."
        fi

        if grep -Fq '"ipv6_mode": "nat66"' "$RUNTIME_SNAPSHOT"; then
            pass "Runtime snapshot confirms IPv6 nat66 mode."
        else
            fail "Runtime snapshot does not confirm ipv6_mode=nat66."
        fi
    else
        if grep -Fq '"tunnel_family": "ipv4"' "$RUNTIME_SNAPSHOT"; then
            pass "Runtime snapshot confirms IPv4 tunnel family."
        else
            fail "Runtime snapshot does not show tunnel_family=ipv4."
        fi

        if grep -Fq '"ipv6_mode": "disabled"' "$RUNTIME_SNAPSHOT"; then
            pass "Runtime snapshot confirms IPv6 is disabled."
        else
            fail "Runtime snapshot does not confirm ipv6_mode=disabled."
        fi
    fi

    if grep -Fq '"profile": "gaming"' "$RUNTIME_SNAPSHOT"; then
        pass "Runtime snapshot is using the gaming profile."
    else
        warn "Runtime snapshot is not using the gaming profile; verify the active profile intentionally."
    fi

    morphing_policy="$(grep -oE '"morphing_policy": "[^"]+"' "$RUNTIME_SNAPSHOT" | head -n1 | sed -E 's/.*"([^"]+)"/\1/')"
    if [[ -n "$morphing_policy" ]]; then
        if [[ "$morphing_policy" == "off" ]]; then
            pass "Runtime snapshot shows OMEGA_MORPHING=off; throughput/latency are prioritized over traffic morphing."
        else
            pass "Runtime snapshot reports morphing policy ${morphing_policy}."
        fi
    else
        warn "Runtime snapshot does not expose morphing_policy yet."
    fi

    avg_loss_ratio="$(grep -oE '"avg_loss_ratio": [0-9.]+' "$RUNTIME_SNAPSHOT" | head -n1 | awk '{print $2}')"
    if [[ -n "$avg_loss_ratio" ]]; then
        if awk "BEGIN { exit !($avg_loss_ratio < 0.02) }"; then
            pass "Average active-session loss ratio is low (${avg_loss_ratio})."
        elif awk "BEGIN { exit !($avg_loss_ratio < 0.05) }"; then
            warn "Average active-session loss ratio is elevated (${avg_loss_ratio}); jitter or retransmits may be visible."
        else
            fail "Average active-session loss ratio is high (${avg_loss_ratio}); expect severe latency spikes."
        fi
    else
        warn "Runtime snapshot does not expose avg_loss_ratio."
    fi
else
    warn "Runtime snapshot file is missing; diagnostics JSON is not being written yet."
fi

if (( fail_count == 0 )); then
    pass "Server path looks Steam/Dota-ready for UDP relay traffic from the VPN side."
else
    fail "Server path is not yet healthy enough for a reliable gaming profile."
fi

warn "Cloud security groups and provider ACLs are outside this script; verify outbound UDP is open."
warn "Client-side DNS policy, IPv6 tunnel policy, and split routes must still be validated on each client host."

echo
echo "[INFO] Summary: ${pass_count} passed, ${warn_count} warnings, ${fail_count} failed."

if (( fail_count > 0 )); then
    exit 1
fi
