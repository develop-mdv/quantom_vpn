#!/bin/bash
set -e

# 1. Detect Primary Interface
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

if [ -z "$IFACE" ]; then
    echo "Error: Could not detect network interface. Please specify manually."
    exit 1
fi

echo "Detected primary interface: $IFACE"

# 2. Backup existing rules
cp /etc/ufw/before.rules /etc/ufw/before.rules.bak
echo "Backed up /etc/ufw/before.rules"

# 3. Check if NAT is already configured
if grep -q "*nat" /etc/ufw/before.rules; then
    echo "NAT *might* already be configured. Please check /etc/ufw/before.rules manually."
    echo "Look for: -A POSTROUTING -s 10.7.0.0/24 -o $IFACE -j MASQUERADE"
else
    # 4. Inject NAT block at the top
    echo "Injecting NAT rules for 10.7.0.0/24 -> $IFACE..."
    
    # We use a temp file to prepend the NAT block
    cat <<EOF > /tmp/ufw_nat.tmp
# START OMEGA VPN NAT
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.7.0.0/24 -o $IFACE -j MASQUERADE
COMMIT
# END OMEGA VPN NAT

EOF
    cat /etc/ufw/before.rules >> /tmp/ufw_nat.tmp
    mv /tmp/ufw_nat.tmp /etc/ufw/before.rules
    echo "NAT rules injected."
fi

# 5. Enable IP Forwarding in UFW
echo "Enabling IP forwarding in /etc/default/ufw..."
sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

# 6. Apply changes
echo "Reloading UFW..."
ufw disable
ufw enable

echo "Done! NAT is configured. Clients should now have internet access."
