#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Omega VPN server network bootstrap.

Usage:
  sudo OMEGA_SSH_PORT=22 OMEGA_VPN_PORT=443 bash setup_nat.sh [public_iface]

Environment:
  OMEGA_PUBLIC_IFACE        public interface, autodetected from default route when empty
  OMEGA_CLIENT_CIDR        VPN client subnet (default: 10.7.0.0/16)
  OMEGA_VPN_PORT           public VPN port (default: 443)
  OMEGA_VPN_PROTO          udp or tcp (default: udp)
  OMEGA_SSH_PORT           SSH port to preserve (default: 22)
  OMEGA_METRICS_PUBLIC     1/0, expose Prometheus metrics publicly (default: 1)
  OMEGA_METRICS_PORT       Prometheus metrics TCP port (default: 9090)
  OMEGA_APPLY_SYSCTL_TUNING 1/0, apply UDP/TCP forwarding tuning (default: 1)
  OMEGA_ENABLE_BBR         1/0, enable BBR when available (default: 1)
  OMEGA_RMEM_MAX           net.core.rmem_max value (default: 8388608)
  OMEGA_WMEM_MAX           net.core.wmem_max value (default: 8388608)
  OMEGA_NETDEV_MAX_BACKLOG net.core.netdev_max_backlog value (default: 4096)
  OMEGA_UDP_RMEM_MIN       net.ipv4.udp_rmem_min value (default: 262144)
  OMEGA_UDP_WMEM_MIN       net.ipv4.udp_wmem_min value (default: 262144)
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
CLIENT_CIDR="${OMEGA_CLIENT_CIDR:-10.7.0.0/16}"
VPN_PORT="${OMEGA_VPN_PORT:-443}"
VPN_PROTO="${OMEGA_VPN_PROTO:-udp}"
SSH_PORT="${OMEGA_SSH_PORT:-22}"
METRICS_PUBLIC="${OMEGA_METRICS_PUBLIC:-1}"
METRICS_PORT="${OMEGA_METRICS_PORT:-9090}"
APPLY_SYSCTL_TUNING="${OMEGA_APPLY_SYSCTL_TUNING:-1}"
ENABLE_BBR="${OMEGA_ENABLE_BBR:-1}"
RMEM_MAX="${OMEGA_RMEM_MAX:-8388608}"
WMEM_MAX="${OMEGA_WMEM_MAX:-8388608}"
NETDEV_MAX_BACKLOG="${OMEGA_NETDEV_MAX_BACKLOG:-4096}"
UDP_RMEM_MIN="${OMEGA_UDP_RMEM_MIN:-262144}"
UDP_WMEM_MIN="${OMEGA_UDP_WMEM_MIN:-262144}"

SYSCTL_FILE="/etc/sysctl.d/99-omega.conf"
UFW_BEFORE_RULES="/etc/ufw/before.rules"
UFW_DEFAULTS="/etc/default/ufw"

if [[ -z "$IFACE" ]]; then
    IFACE="$(ip route | awk '/default/ {print $5; exit}')"
fi

if [[ -z "$IFACE" ]]; then
    echo "[ERROR] Could not detect public interface. Set OMEGA_PUBLIC_IFACE or pass it as the first argument."
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

require_numeric "$VPN_PORT" "OMEGA_VPN_PORT"
require_numeric "$SSH_PORT" "OMEGA_SSH_PORT"
require_numeric "$METRICS_PORT" "OMEGA_METRICS_PORT"
require_numeric "$RMEM_MAX" "OMEGA_RMEM_MAX"
require_numeric "$WMEM_MAX" "OMEGA_WMEM_MAX"
require_numeric "$NETDEV_MAX_BACKLOG" "OMEGA_NETDEV_MAX_BACKLOG"
require_numeric "$UDP_RMEM_MIN" "OMEGA_UDP_RMEM_MIN"
require_numeric "$UDP_WMEM_MIN" "OMEGA_UDP_WMEM_MIN"

if [[ "$VPN_PROTO" != "udp" && "$VPN_PROTO" != "tcp" ]]; then
    echo "[ERROR] OMEGA_VPN_PROTO must be either 'udp' or 'tcp'."
    exit 1
fi

if ! command -v ufw >/dev/null 2>&1; then
    echo "[ERROR] ufw is not installed."
    exit 1
fi

backup_file() {
    local path="$1"
    local backup="${path}.omega.bak"
    if [[ ! -f "$backup" ]]; then
        cp "$path" "$backup"
        echo "[INFO] Backed up $path to $backup"
    fi
}

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

    sysctl -w "${key}=${value}" >/dev/null
}

input_rule_healthy() {
    local proto="$1"
    local port="$2"
    local status

    status="$(ufw status 2>/dev/null || true)"
    grep -Eiq "\\b${port}/${proto}\\b.*ALLOW" <<<"$status"
}

nat_rule_active() {
    if ! command -v iptables >/dev/null 2>&1; then
        return 0
    fi
    iptables -t nat -S POSTROUTING | grep -Fq -- "$NAT_RULE"
}

repair_ufw_hooks() {
    echo "[WARN] Re-enabling UFW to repair missing hooks..."
    ufw disable || true
    ufw --force enable
}

forward_policy_healthy() {
    grep -Eq '^DEFAULT_FORWARD_POLICY="ACCEPT"' "$UFW_DEFAULTS"
}

NAT_RULE="-A POSTROUTING -s ${CLIENT_CIDR} -o ${IFACE} -j MASQUERADE"
MSS_RULE="-A FORWARD -s ${CLIENT_CIDR} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"

echo "[INFO] Public interface: ${IFACE}"
echo "[INFO] VPN client subnet: ${CLIENT_CIDR}"
echo "[INFO] Preserving SSH on: ${SSH_PORT}/tcp"
echo "[INFO] Allowing VPN on: ${VPN_PORT}/${VPN_PROTO}"
if [[ "$METRICS_PUBLIC" == "1" ]]; then
    echo "[INFO] Exposing Prometheus metrics on: ${METRICS_PORT}/tcp"
else
    echo "[INFO] Public Prometheus metrics are disabled."
fi

backup_file "$UFW_BEFORE_RULES"
backup_file "$UFW_DEFAULTS"

if grep -Fq -- "$NAT_RULE" "$UFW_BEFORE_RULES"; then
    echo "[INFO] NAT rule already present."
elif grep -q "^\*nat" "$UFW_BEFORE_RULES"; then
    echo "[INFO] Injecting NAT rule into existing *nat table..."
    tmp_file="$(mktemp)"
    awk -v rule="$NAT_RULE" '
        BEGIN { in_nat=0; inserted=0 }
        {
            if ($0 == "*nat") {
                in_nat=1
            }
            if (in_nat && $0 == "COMMIT" && !inserted) {
                print rule
                inserted=1
            }
            print
            if (in_nat && $0 == "COMMIT") {
                in_nat=0
            }
        }
        END {
            if (!inserted) exit 1
        }
    ' "$UFW_BEFORE_RULES" > "$tmp_file"
    mv "$tmp_file" "$UFW_BEFORE_RULES"
else
    echo "[INFO] Injecting NAT block for ${CLIENT_CIDR} -> ${IFACE}..."
    tmp_file="$(mktemp)"
    cat <<EOF > "$tmp_file"
# START OMEGA VPN NAT
*nat
:POSTROUTING ACCEPT [0:0]
$NAT_RULE
COMMIT
# END OMEGA VPN NAT
EOF
    cat "$UFW_BEFORE_RULES" >> "$tmp_file"
    mv "$tmp_file" "$UFW_BEFORE_RULES"
fi

if grep -Fq -- "$MSS_RULE" "$UFW_BEFORE_RULES"; then
    echo "[INFO] MSS clamping rule already present."
elif grep -q "^\*filter" "$UFW_BEFORE_RULES"; then
    echo "[INFO] Injecting MSS clamping rule into existing *filter table..."
    tmp_file="$(mktemp)"
    awk -v rule="$MSS_RULE" '
        BEGIN { in_filter=0; inserted=0 }
        {
            if ($0 == "*filter") {
                in_filter=1
            }
            if (in_filter && $0 == "COMMIT" && !inserted) {
                print rule
                inserted=1
            }
            print
            if (in_filter && $0 == "COMMIT") {
                in_filter=0
            }
        }
        END {
            if (!inserted) exit 1
        }
    ' "$UFW_BEFORE_RULES" > "$tmp_file"
    mv "$tmp_file" "$UFW_BEFORE_RULES"
else
    echo "[INFO] Injecting standalone MSS clamping block..."
    cat <<EOF >> "$UFW_BEFORE_RULES"
# START OMEGA VPN MSS CLAMPING
*filter
:FORWARD ACCEPT [0:0]
$MSS_RULE
COMMIT
# END OMEGA VPN MSS CLAMPING
EOF
fi

ufw allow "${SSH_PORT}/tcp"
ufw allow "${VPN_PORT}/${VPN_PROTO}"
if [[ "$METRICS_PUBLIC" == "1" ]]; then
    ufw allow "${METRICS_PORT}/tcp"
fi

echo "[INFO] Enabling IPv4 forwarding..."
persist_sysctl "net.ipv4.ip_forward" "1"

if [[ "$APPLY_SYSCTL_TUNING" == "1" ]]; then
    echo "[INFO] Applying network tuning for VPN + game traffic..."
    persist_sysctl "net.core.rmem_max" "$RMEM_MAX"
    persist_sysctl "net.core.wmem_max" "$WMEM_MAX"
    persist_sysctl "net.core.netdev_max_backlog" "$NETDEV_MAX_BACKLOG"
    persist_sysctl "net.ipv4.udp_rmem_min" "$UDP_RMEM_MIN"
    persist_sysctl "net.ipv4.udp_wmem_min" "$UDP_WMEM_MIN"
    persist_sysctl "net.ipv4.tcp_mtu_probing" "1"
    persist_sysctl "net.ipv4.conf.all.rp_filter" "2"
    persist_sysctl "net.ipv4.conf.default.rp_filter" "2"

    if [[ "$ENABLE_BBR" == "1" ]]; then
        available_cc="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
        if grep -qw "bbr" <<<"$available_cc"; then
            persist_sysctl "net.core.default_qdisc" "fq"
            persist_sysctl "net.ipv4.tcp_congestion_control" "bbr"
            echo "[INFO] BBR enabled."
        else
            echo "[WARN] BBR is not available on this kernel, skipping."
        fi
    fi
fi

echo "[INFO] Enabling forwarding policy in UFW..."
if grep -q '^DEFAULT_FORWARD_POLICY=' "$UFW_DEFAULTS"; then
    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' "$UFW_DEFAULTS"
else
    printf 'DEFAULT_FORWARD_POLICY="ACCEPT"\n' >> "$UFW_DEFAULTS"
fi

echo "[INFO] Reloading UFW..."
if ufw status | grep -q '^Status: active'; then
    ufw reload
else
    ufw --force enable
fi

if ! input_rule_healthy tcp "$SSH_PORT" || ! input_rule_healthy "$VPN_PROTO" "$VPN_PORT"; then
    repair_ufw_hooks
fi

if ! input_rule_healthy tcp "$SSH_PORT"; then
    echo "[ERROR] SSH allow rule is not visible in active UFW state."
    echo "[ERROR] Aborting before any SSH-breaking change is considered successful."
    exit 1
fi

if ! input_rule_healthy "$VPN_PROTO" "$VPN_PORT"; then
    echo "[ERROR] VPN allow rule is not visible in active UFW state."
    exit 1
fi

if [[ "$METRICS_PUBLIC" == "1" ]] && ! input_rule_healthy tcp "$METRICS_PORT"; then
    echo "[ERROR] Metrics allow rule is not visible in active UFW state."
    exit 1
fi

if ! forward_policy_healthy; then
    echo "[ERROR] DEFAULT_FORWARD_POLICY is not ACCEPT."
    exit 1
fi

if ! nat_rule_active; then
    echo "[WARN] NAT rule is missing after reload, attempting UFW repair..."
    repair_ufw_hooks
fi

if ! nat_rule_active; then
    echo "[ERROR] Active POSTROUTING chain does not contain the expected NAT rule."
    exit 1
fi

echo
echo "[INFO] Server-side Steam readiness summary:"
echo "  - Remote TCP allowed through the VPN path: 80, 443, 27015-27050"
echo "  - Remote UDP allowed through the VPN path: 3478, 4379, 4380, 27000-27100, 27014-27050"
echo "  - Steam Remote Play local ports (27031-27036/udp, 27036/tcp) must stay open on the client OS"
echo "  - Valve IPv6 prefixes are not covered yet because Omega currently tunnels IPv4 only"
echo
echo "[INFO] NAT and forwarding are configured. Current UFW status:"
ufw status verbose

if [[ "$METRICS_PUBLIC" == "1" ]]; then
    echo "[INFO] Prometheus metrics should be reachable at http://<server-ip>:${METRICS_PORT}/"
fi

if command -v ss >/dev/null 2>&1; then
    echo
    echo "[INFO] Active ${VPN_PROTO^^} listeners on port ${VPN_PORT}:"
    if [[ "$VPN_PROTO" == "udp" ]]; then
        ss -lunp | grep -E "[[:space:]]:${VPN_PORT}[[:space:]]" || true
    else
        ss -ltnp | grep -E "[[:space:]]:${VPN_PORT}[[:space:]]" || true
    fi
    if [[ "$METRICS_PUBLIC" == "1" ]]; then
        echo "[INFO] Active TCP listeners on metrics port ${METRICS_PORT}:"
        ss -ltnp | grep -E "[[:space:]]:${METRICS_PORT}[[:space:]]" || true
    fi
fi
