#!/usr/bin/env bash
set -e

echo "🧹 Cleaning up old processes…"

# 0) Stop NetworkManager to prevent automatic reconnections
echo "  • Stopping NetworkManager..."
sudo systemctl stop NetworkManager 2>/dev/null || true
sudo rfkill unblock wifi # Ensure WiFi isn't blocked

# 1) Stop/kick any system dnsmasq
echo "  • Stopping system dnsmasq..."
sudo systemctl stop dnsmasq.service 2>/dev/null || true
sudo pkill -9 dnsmasq                   2>/dev/null || true

# 2) Kill attack services
echo "  • Stopping hostapd, dnsmasq, dnsspoof..."
sudo pkill -f hostapd                   2>/dev/null || true
sudo pkill -f dnsmasq                   2>/dev/null || true
sudo pkill -f dnsspoof                  2>/dev/null || true

# 3) Flush iptables tables
echo "  • Flushing iptables tables..."
sudo iptables -t nat -F
sudo iptables -t filter -F
sudo iptables -t mangle -F

# 3a) Delete custom CAPTIVE chain if present
if sudo iptables -t nat -L | grep -q CAPTIVE; then
  echo "  • Deleting custom NAT chain CAPTIVE..."
  sudo iptables -t nat -X CAPTIVE
fi

# 4) Tear down ap0 if it exists
if ip link show ap0 &>/dev/null; then
  echo "  • Removing ap0 interface and addresses..."
  sudo ip addr flush dev ap0 2>/dev/null || true
  sudo ip link set ap0 down
  sudo iw dev ap0 del
fi

# 5) Disconnect from any active networks
MON_IF=wlxe84e06aed7ca
AP_PHY=phy0
AP_DEV=wlo1

echo "  • Disconnecting from any networks..."
sudo iw dev "$MON_IF" disconnect 2>/dev/null || true
sudo iw dev "$AP_DEV" disconnect 2>/dev/null || true

# 6) Sniffer → monitor mode using modern iw commands
echo "  • Putting $MON_IF into monitor mode…"
sudo ip link set "$MON_IF" down
sudo iw dev "$MON_IF" set type monitor
sudo ip link set "$MON_IF" up

# 7) Create AP interface - MODIFIED APPROACH
echo "  • Creating AP interface..."
# First check if card supports AP mode
echo "  • Checking AP mode support..."
if ! iw list | grep -A 10 "Supported interface modes" | grep -q "AP"; then
  echo "WARNING: Your wireless card may not support AP mode!"
  echo "Will try to proceed anyway."
fi

# Try creating ap0 with regular managed type first
sudo ip link set "$AP_DEV" down
sudo iw dev "$AP_DEV" interface add ap0 type managed 2>/dev/null || {
  # If that fails, try with __ap type
  sudo iw phy "$AP_PHY" interface add ap0 type __ap 2>/dev/null || {
    # Last resort - just use the interface directly
    echo "  • Could not create virtual interface, using $AP_DEV directly"
    AP_IF="$AP_DEV"
    sudo ip link set "$AP_DEV" up
    # Skip verification since we're not using ap0
    echo
    echo "✅ Interfaces ready:"
    echo "  Sniffer: $MON_IF"
    iw dev "$MON_IF" info | head -3
    echo
    echo "  Evil-AP: $AP_IF (using directly)"
    iw dev "$AP_IF" info | head -3
    echo
    echo "Use sniffer='$MON_IF' and ap_iface='$AP_IF' in your Python tool."
    echo "NOTE: NetworkManager is stopped to prevent automatic reconnections."
    exit 0
  }
}

sudo ip link set ap0 up
AP_IF=ap0
echo "  → Virtual ap0 created"

# The verification step is unnecessary as hostapd will set the mode
# Instead, just display what we have
echo
echo "✅ Interfaces ready:"
echo "  Sniffer: $MON_IF"
iw dev "$MON_IF" info | head -3
echo
echo "  Evil-AP: $AP_IF"
iw dev "$AP_IF" info | head -3
echo
echo "Use sniffer='$MON_IF' and ap_iface='$AP_IF' in your Python tool."
echo "NOTE: hostapd will set the AP mode when it starts."