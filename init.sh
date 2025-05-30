#!/usr/bin/env bash
set -e

echo "🧹 Cleaning up old processes…"
sudo airmon-ng check kill   # kill NetworkManager/wpa_supplicant
sudo pkill -f hostapd       2>/dev/null || true
sudo pkill -f dnsmasq       2>/dev/null || true

# — Sniffer card → monitor mode —
MON_IF=wlxe84e06aed7ca
echo "➜ Putting $MON_IF into MONITOR mode…"
sudo ip link set  "$MON_IF" down
sudo iwconfig   "$MON_IF" mode monitor
sudo ip link set  "$MON_IF" up

# — Attempt in-place AP mode on built-in card —
AP_PHY=phy0          # adjust if your built-in is on a different phy
AP_DEV=wlo1
echo "➜ Trying to put $AP_DEV into MASTER mode…"
if sudo ip link set "$AP_DEV" down &&
   sudo iwconfig   "$AP_DEV" mode master 2>/dev/null &&
   sudo ip link set "$AP_DEV" up
then
  AP_IF="$AP_DEV"
  echo "✔︎ $AP_DEV is now in AP mode"
else
  # fallback to virtual ap0 on the same PHY
  echo "⚠️  $AP_DEV won’t go AP mode in-place; creating virtual ap0…"
  sudo iw phy "$AP_PHY" interface add ap0 type __ap
  AP_IF=ap0
  sudo ip link set ap0 up
  echo "✔︎ Virtual interface ap0 created (AP mode)"
fi

echo
echo "✅ Interfaces ready:"
echo "  Sniffer: $MON_IF (monitor mode)"
iwconfig "$MON_IF" | sed -n '1,2p'
echo
echo "  Evil-AP: $AP_IF"
iwconfig "$AP_IF" | sed -n '1,2p'
echo
echo "Use sniffer='$MON_IF' and ap_iface='$AP_IF' in your Python tool."
