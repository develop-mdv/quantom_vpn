#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Omega VPN server diagnostics.

Usage:
  sudo bash diagnose_server.sh [public_iface]

Environment:
  OMEGA_PUBLIC_IFACE  public interface, autodetected from default route when empty
  OMEGA_CLIENT_CIDR   VPN client subnet (default: 10.7.0.0/16)
  OMEGA_VPN_PORT      public VPN port (default: 443)
  OMEGA_VPN_PROTO     udp or tcp (default: udp)
  OMEGA_SSH_PORT      SSH port that must remain reachable (default: 22)
  OMEGA_METRICS_PUBLIC 1/0, expect public Prometheus metrics (default: 1)
  OMEGA_METRICS_PORT  public Prometheus metrics TCP port (default: 9090)
  OMEGA_SERVICE_NAME  systemd service name (default: omega-server)
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

IFACE="${OMEGA_PUBLIC_IFACE:-${1:-}}"
CLIENT_CIDR="${OMEGA_CLIENT_CIDR:-10.7.0.0/16}"
VPN_PORT="${OMEGA_VPN_PORT:-443}"
VPN_PROTO="${OMEGA_VPN_PROTO:-udp}"
SSH_PORT="${OMEGA_SSH_PORT:-22}"
METRICS_PUBLIC="${OMEGA_METRICS_PUBLIC:-1}"
METRICS_PORT="${OMEGA_METRICS_PORT:-9090}"
SERVICE_NAME="${OMEGA_SERVICE_NAME:-omega-server}"

if [[ -z "$IFACE" ]]; then
    IFACE="$(ip route | awk '/default/ {print $5; exit}')"
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

is_listener_exposed() {
    local port="$1"
    if ! cmd_exists ss; then
        return 1
    fi
    ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|\\[::\\]:|0\\.0\\.0\\.0:)${port}$"
}

check_udp_listener() {
    if ! cmd_exists ss; then
        warn "ss is not installed; cannot verify runtime listener state."
        return
    fi
    if ss -H -lun 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${VPN_PORT}$"; then
        pass "UDP listener is present on port ${VPN_PORT}."
    else
        fail "UDP listener on port ${VPN_PORT} is not visible."
    fi
}

check_tcp_listener() {
    if ! cmd_exists ss; then
        warn "ss is not installed; cannot verify runtime listener state."
        return
    fi
    if ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${VPN_PORT}$"; then
        pass "TCP listener is present on port ${VPN_PORT}."
    else
        fail "TCP listener on port ${VPN_PORT} is not visible."
    fi
}

ufw_status="$(ufw status 2>/dev/null || true)"
unit_dump="$(systemctl cat "$SERVICE_NAME" 2>/dev/null || true)"

echo "[INFO] Public interface: ${IFACE:-unknown}"
echo "[INFO] Client subnet: ${CLIENT_CIDR}"
echo "[INFO] VPN public port: ${VPN_PORT}/${VPN_PROTO}"
echo "[INFO] SSH port: ${SSH_PORT}/tcp"
if [[ "$METRICS_PUBLIC" == "1" ]]; then
    echo "[INFO] Public metrics port: ${METRICS_PORT}/tcp"
else
    echo "[INFO] Public metrics: disabled"
fi
echo "[INFO] Service: ${SERVICE_NAME}"
echo

if [[ "$(id -u)" -ne 0 ]]; then
    warn "Running without root; some iptables and system checks may be incomplete."
fi

if cmd_exists sysctl; then
    if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" == "1" ]]; then
        pass "IPv4 forwarding is enabled."
    else
        fail "IPv4 forwarding is disabled."
    fi

    rmem_max="$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)"
    wmem_max="$(sysctl -n net.core.wmem_max 2>/dev/null || echo 0)"
    if (( rmem_max >= 8388608 )); then
        pass "net.core.rmem_max is tuned for larger UDP bursts (${rmem_max})."
    else
        warn "net.core.rmem_max is low (${rmem_max}); high-rate UDP can drop under burst load."
    fi
    if (( wmem_max >= 8388608 )); then
        pass "net.core.wmem_max is tuned for larger UDP bursts (${wmem_max})."
    else
        warn "net.core.wmem_max is low (${wmem_max}); outbound burst handling can suffer."
    fi

    rp_all="$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo 0)"
    rp_default="$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null || echo 0)"
    if [[ "$rp_all" == "2" && "$rp_default" == "2" ]]; then
        pass "rp_filter is set to loose mode (2), which is safer for tunneled/NATed paths."
    else
        warn "rp_filter is not set to loose mode (all=${rp_all}, default=${rp_default})."
    fi
else
    warn "sysctl is not available; kernel tuning checks skipped."
fi

if [[ -n "$ufw_status" && "$ufw_status" != "Status: inactive" ]]; then
    pass "UFW is active."
else
    fail "UFW is inactive or unavailable."
fi

if grep -Eiq "\\b${SSH_PORT}/tcp\\b.*ALLOW" <<<"$ufw_status"; then
    pass "SSH allow rule is present in UFW."
else
    fail "SSH allow rule for ${SSH_PORT}/tcp is missing in UFW."
fi

if grep -Eiq "\\b${VPN_PORT}/${VPN_PROTO}\\b.*ALLOW" <<<"$ufw_status"; then
    pass "VPN allow rule is present in UFW."
else
    fail "VPN allow rule for ${VPN_PORT}/${VPN_PROTO} is missing in UFW."
fi

if [[ "$METRICS_PUBLIC" == "1" ]]; then
    if grep -Eiq "\\b${METRICS_PORT}/tcp\\b.*ALLOW" <<<"$ufw_status"; then
        pass "Metrics allow rule is present in UFW."
    else
        fail "Metrics allow rule for ${METRICS_PORT}/tcp is missing in UFW."
    fi
fi

if grep -Eq '^DEFAULT_FORWARD_POLICY="ACCEPT"' /etc/default/ufw 2>/dev/null; then
    pass "UFW forward policy is ACCEPT."
else
    fail "UFW forward policy is not ACCEPT."
fi

if cmd_exists iptables; then
    nat_rule="-A POSTROUTING -s ${CLIENT_CIDR} -o ${IFACE} -j MASQUERADE"
    if iptables -t nat -S POSTROUTING 2>/dev/null | grep -Fq -- "$nat_rule"; then
        pass "IPv4 NAT rule for ${CLIENT_CIDR} -> ${IFACE} is active."
    else
        fail "IPv4 NAT rule for ${CLIENT_CIDR} -> ${IFACE} is missing."
    fi
else
    warn "iptables is not available; NAT verification skipped."
fi

if systemctl is-active --quiet "$SERVICE_NAME"; then
    pass "systemd service ${SERVICE_NAME} is active."
else
    fail "systemd service ${SERVICE_NAME} is not active."
fi

if [[ "$VPN_PROTO" == "udp" ]]; then
    check_udp_listener
else
    check_tcp_listener
fi

if is_listener_exposed 8081; then
    warn "Admin web UI is listening on a public address. Prefer 127.0.0.1:8081 plus SSH tunnel or reverse proxy."
elif grep -Fq 'OMEGA_ADMIN_WEB_BIND=0.0.0.0:8081' <<<"$unit_dump"; then
    warn "Service template exposes admin web UI publicly."
else
    pass "Admin web UI is not exposed publicly by default."
fi

if [[ "$METRICS_PUBLIC" == "1" ]]; then
    if is_listener_exposed "$METRICS_PORT"; then
        pass "Prometheus metrics are exposed publicly on port ${METRICS_PORT}."
    elif grep -Fq "OMEGA_METRICS_BIND=0.0.0.0:${METRICS_PORT}" <<<"$unit_dump"; then
        warn "Service template expects public metrics, but the listener is not up yet."
    else
        fail "Prometheus metrics are not exposed publicly on port ${METRICS_PORT}."
    fi
elif is_listener_exposed "$METRICS_PORT"; then
    warn "Prometheus metrics are listening on a public address unexpectedly."
else
    pass "Prometheus metrics are not exposed publicly by default."
fi

if (( fail_count == 0 )); then
    pass "Server-side IPv4 full-tunnel path is ready for Steam remote ports: TCP 80/443/27015-27050 and UDP 3478/4379/4380/27000-27100/27014-27050."
else
    fail "Server-side Steam IPv4 path is not fully healthy because one or more prerequisite checks failed."
fi

warn "Steam client-local ports 27031-27036/udp and 27036/tcp are not controlled by the VPN server; keep them open on each client host."
warn "Valve IPv6 prefixes are not fully covered because the current Omega tunnel is IPv4-only."

echo
echo "[INFO] Summary: ${pass_count} passed, ${warn_count} warnings, ${fail_count} failed."

if (( fail_count > 0 )); then
    exit 1
fi
