#!/usr/bin/env bash
set -e

echo "🧹 Cleaning up Evil‑Twin Attack environment…"

# 1) Kill attack services
echo "  • Stopping hostapd, dnsmasq, dnsspoof..."
sudo pkill -f hostapd    2>/dev/null || true
sudo pkill -f dnsmasq     2>/dev/null || true
sudo pkill -f dnsspoof    2>/dev/null || true

# 2) Flush iptables rules (NAT + filter)
echo "  • Flushing iptables rules..."
sudo iptables -t nat -F
sudo iptables -F

# 3) Remove hostapd and dnsmasq configs
echo "  • Removing hostapd and dnsmasq configs..."
sudo rm -f hostapd.conf
sudo rm -f dnsmasq.conf

# 4) Disable IP forwarding
echo "  • Disabling IPv4 forwarding..."
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null

# 5) Restart NetworkManager (or networking.service)
echo "  • Restarting NetworkManager..."
sudo systemctl restart NetworkManager