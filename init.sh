#!/usr/bin/env bash
set -e

echo "🧹 Cleaning up old processes…"

# 0) Stop/kick any system dnsmasq
echo "  • Stopping system dnsmasq..."
sudo systemctl stop dnsmasq.service 2>/dev/null || true
sudo pkill -9 dnsmasq                   2>/dev/null || true

# 1) Kill attack services
echo "  • Stopping hostapd, dnsmasq, dnsspoof..."
sudo pkill -f hostapd                   2>/dev/null || true
sudo pkill -f dnsmasq                   2>/dev/null || true
sudo pkill -f dnsspoof                  2>/dev/null || true

# 2) Flush iptables tables
echo "  • Flushing iptables tables..."
sudo iptables -t nat -F
sudo iptables -t filter -F
sudo iptables -t mangle -F

# 2a) Delete custom CAPTIVE chain if present
if sudo iptables -t nat -L | grep -q CAPTIVE; then
  echo "  • Deleting custom NAT chain CAPTIVE..."
  sudo iptables -t nat -X CAPTIVE
fi

# 3) Tear down ap0 if it exists
if ip link show ap0 &>/dev/null; then
  echo "  • Removing ap0 interface and addresses..."
  sudo ip addr flush dev ap0 2>/dev/null || true
  sudo ip link set ap0 down
  sudo iw dev ap0 del
fi

# 4) Sniffer → monitor mode
MON_IF=wlxe84e06aed7ca
echo "  • Putting $MON_IF into monitor mode…"
sudo ip link set  "$MON_IF" down
sudo iwconfig   "$MON_IF" mode monitor
sudo ip link set  "$MON_IF" up

# 5) Attempt in-place AP mode or fallback
AP_PHY=phy0
AP_DEV=wlo1
echo "  • Setting up AP on $AP_DEV…"
if sudo ip link set "$AP_DEV" down &&
   sudo iwconfig "$AP_DEV" mode master 2>/dev/null &&
   sudo ip link set "$AP_DEV" up
then
  AP_IF="$AP_DEV"
  echo "    → $AP_DEV is now in AP mode"
else
  echo "    → $AP_DEV won’t do master mode; creating ap0…"
  sudo iw phy "$AP_PHY" interface add ap0 type __ap
  AP_IF=ap0
  sudo ip addr flush dev ap0
  sudo ip link set ap0 up
  echo "    → Virtual ap0 created"
fi

echo
echo "✅ Interfaces ready:"
echo "  Sniffer: $MON_IF"
iwconfig "$MON_IF" | sed -n '1,2p'
echo
echo "  Evil-AP: $AP_IF"
iwconfig "$AP_IF" | sed -n '1,2p'
echo
echo "Use sniffer='$MON_IF' and ap_iface='$AP_IF' in your Python tool."
