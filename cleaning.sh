#!/usr/bin/env bash
set -e

echo "🧹 Cleaning up Evil‑Twin Attack environment…"

# 1) Kill attack services
echo "  • Stopping hostapd, dnsmasq, dnsspoof..."
sudo pkill -f hostapd    2>/dev/null || true
sudo pkill -f dnsmasq     2>/dev/null || true
sudo pkill -f dnsspoof    2>/dev/null || true

# 2) Flush iptables rules (NAT + filter + mangle)
echo "  • Flushing iptables tables..."
sudo iptables -t nat -F
sudo iptables -t filter -F
sudo iptables -t mangle -F

# 2a) Delete our custom NAT chain if it exists
if sudo iptables -t nat -L | grep -q CAPTIVE; then
  echo "  • Deleting custom NAT chain CAPTIVE..."
  sudo iptables -t nat -X CAPTIVE
fi

# 3) Tear down the virtual AP interface if present
if ip link show ap0 &>/dev/null; then
  echo "  • Bringing down ap0 and removing IP..."
  sudo ip link set ap0 down
  sudo ip addr del 192.168.1.1/24 dev ap0 2>/dev/null || true

  echo "  • Deleting virtual interface ap0..."
  sudo iw dev ap0 del
fi

# 4) Remove hostapd and dnsmasq configs
echo "  • Removing hostapd and dnsmasq configs..."
sudo rm -f hostapd.conf dnsmasq.conf

# 5) Disable IP forwarding
echo "  • Disabling IPv4 forwarding..."
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null

# 6) Restore NetworkManager management of WiFi interfaces
echo "  • Restoring NetworkManager management of WiFi interfaces..."
sudo nmcli device set wlo1 managed yes 2>/dev/null || true
sudo nmcli device set wlxe84e06aed7ca managed yes 2>/dev/null || true

# Remove NetworkManager configuration for ap0
echo "  • Removing NetworkManager ap0 exclusion..."
sudo rm -f /etc/NetworkManager/conf.d/evil-twin-unmanaged.conf
sudo systemctl reload NetworkManager 2>/dev/null || true

# Reset interface states
echo "  • Resetting interface states..."
sudo ip link set wlo1 down 2>/dev/null || true
sudo ip link set wlxe84e06aed7ca down 2>/dev/null || true
sudo ip link set wlo1 up 2>/dev/null || true  
sudo ip link set wlxe84e06aed7ca up 2>/dev/null || true

echo "✅ Cleanup complete."
