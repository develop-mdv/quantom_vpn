#!/usr/bin/env bash
set -euo pipefail

IFACE="${OMEGA_PUBLIC_IFACE:-${1:-}}"
VPN_PORT="${OMEGA_VPN_PORT:-443}"
VPN_PROTO="${OMEGA_VPN_PROTO:-udp}"
SSH_PORT="${OMEGA_SSH_PORT:-22}"
SYSCTL_FILE="/etc/sysctl.d/99-omega.conf"

if [[ -z "$IFACE" ]]; then
    IFACE="$(ip route | awk '/default/ {print $5; exit}')"
fi

if [[ -z "$IFACE" ]]; then
    echo "[ERROR] Could not detect network interface. Specify OMEGA_PUBLIC_IFACE or pass it as the first argument."
    exit 1
fi

if ! [[ "$VPN_PORT" =~ ^[0-9]+$ ]]; then
    echo "[ERROR] OMEGA_VPN_PORT must be numeric."
    exit 1
fi

if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]]; then
    echo "[ERROR] OMEGA_SSH_PORT must be numeric."
    exit 1
fi

if [[ "$VPN_PROTO" != "udp" && "$VPN_PROTO" != "tcp" ]]; then
    echo "[ERROR] OMEGA_VPN_PROTO must be either 'udp' or 'tcp'."
    exit 1
fi

if ! command -v ufw >/dev/null 2>&1; then
    echo "[ERROR] ufw is not installed."
    exit 1
fi

echo "Using public interface: $IFACE"
echo "Allowing SSH on port: $SSH_PORT/tcp"
echo "Allowing VPN on port: $VPN_PORT/$VPN_PROTO"

# 2. Backup existing rules
cp /etc/ufw/before.rules /etc/ufw/before.rules.bak
echo "Backed up /etc/ufw/before.rules"

# 3. Ensure NAT and MSS rules are present
NAT_RULE="-A POSTROUTING -s 10.7.0.0/16 -o $IFACE -j MASQUERADE"
MSS_RULE="-A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"

if grep -Fq -- "$NAT_RULE" /etc/ufw/before.rules; then
    echo "NAT rule already present."
elif grep -q "^\*nat" /etc/ufw/before.rules; then
    echo "Injecting NAT rule into existing *nat table..."
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
    ' /etc/ufw/before.rules > /tmp/ufw_nat.tmp
    mv /tmp/ufw_nat.tmp /etc/ufw/before.rules
else
    echo "Injecting NAT block for 10.7.0.0/16 -> $IFACE..."
    cat <<EOF > /tmp/ufw_nat.tmp
# START OMEGA VPN NAT
*nat
:POSTROUTING ACCEPT [0:0]
$NAT_RULE
COMMIT
# END OMEGA VPN NAT
EOF
    cat /etc/ufw/before.rules >> /tmp/ufw_nat.tmp
    mv /tmp/ufw_nat.tmp /etc/ufw/before.rules
fi

if grep -Fq -- "$MSS_RULE" /etc/ufw/before.rules; then
    echo "MSS clamping rule already present."
elif grep -q "^\*filter" /etc/ufw/before.rules; then
    echo "Injecting MSS clamping rule into existing *filter table..."
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
    ' /etc/ufw/before.rules > /tmp/ufw_filter.tmp
    mv /tmp/ufw_filter.tmp /etc/ufw/before.rules
else
    echo "Injecting standalone MSS clamping block..."
    cat <<EOF >> /etc/ufw/before.rules
# START OMEGA VPN MSS CLAMPING
*filter
:FORWARD ACCEPT [0:0]
$MSS_RULE
COMMIT
# END OMEGA VPN MSS CLAMPING
EOF
fi

# 5. Allow required inbound traffic
ufw allow "${SSH_PORT}/tcp"
ufw allow "${VPN_PORT}/${VPN_PROTO}"

# 6. Enable kernel IP forwarding now and persist it
echo "Enabling net.ipv4.ip_forward..."
sysctl -w net.ipv4.ip_forward=1
if [[ -f "$SYSCTL_FILE" ]] && grep -q '^net\.ipv4\.ip_forward=' "$SYSCTL_FILE"; then
    sed -i 's/^net\.ipv4\.ip_forward=.*/net.ipv4.ip_forward=1/' "$SYSCTL_FILE"
else
    printf 'net.ipv4.ip_forward=1\n' >> "$SYSCTL_FILE"
fi

# 7. Enable IP forwarding in UFW
echo "Enabling IP forwarding in /etc/default/ufw..."
if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
else
    printf 'DEFAULT_FORWARD_POLICY="ACCEPT"\n' >> /etc/default/ufw
fi

# 8. Apply changes
echo "Reloading UFW..."
if ufw status | grep -q '^Status: active'; then
    ufw reload
else
    ufw --force enable
fi

repair_ufw_hooks() {
    echo "[WARN] Re-enabling UFW to repair missing IPv4 base hooks..."
    ufw disable || true
    ufw --force enable
}

input_hook_attached() {
    if ! command -v iptables >/dev/null 2>&1; then
        return 0
    fi
    iptables -S INPUT | grep -q 'ufw-before-input'
}

nat_rule_active() {
    if ! command -v iptables >/dev/null 2>&1; then
        return 0
    fi
    iptables -t nat -S POSTROUTING | grep -Fq -- "$NAT_RULE"
}

# 9. Verify that IPv4 UFW hooks are actually attached and NAT is active.
# Without these checks, UFW can report "active" while IPv4 INPUT is still
# effectively dropped due to missing base-chain jumps.
if ! input_hook_attached; then
    repair_ufw_hooks
fi

if ! input_hook_attached; then
    echo "[ERROR] IPv4 INPUT is not hooked into UFW chains."
    echo "[ERROR] Inbound IPv4 traffic (including SSH/VPN) may still be dropped."
    echo "[ERROR] Verify UFW initialization and inspect /etc/ufw/*.rules for corruption."
    exit 1
fi

if ! nat_rule_active; then
    echo "[WARN] Expected NAT rule is missing after reload. Re-enabling UFW to repair NAT..."
    repair_ufw_hooks
fi

if ! nat_rule_active; then
    echo "[ERROR] Expected NAT rule is missing from the active POSTROUTING chain."
    echo "[ERROR] Clients may connect to the tunnel but still lose internet access."
    exit 1
fi

echo "Done! NAT is configured. Clients should now have internet access."
ufw status verbose

if command -v ss >/dev/null 2>&1; then
    echo "[INFO] Active ${VPN_PROTO^^} listeners on port ${VPN_PORT}:"
    if [[ "$VPN_PROTO" == "udp" ]]; then
        ss -lunp | grep -E "[[:space:]]:${VPN_PORT}[[:space:]]" || true
    else
        ss -ltnp | grep -E "[[:space:]]:${VPN_PORT}[[:space:]]" || true
    fi
fi
