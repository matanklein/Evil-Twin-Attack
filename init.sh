#!/usr/bin/env bash
set -e

echo "🧹 Full cleanup of old Wi-Fi interfaces…"

# Stop NetworkManager and kill wpa_supplicant
sudo airmon-ng check kill || true

# Kill any hostapd/dnsmasq
sudo pkill -f hostapd   2>/dev/null || true
sudo pkill -f dnsmasq    2>/dev/null || true

# Delete *all* monitor and AP virtual interfaces via ip link first  
for IF in $(ip -o link show | awk -F': ' '{print $2}'); do
  if [[ $IF =~ ^mon|^ap ]]; then
    echo "  • Deleting $IF"
    sudo ip link delete $IF      2>/dev/null || true
  fi
done

# Then also delete any leftover 802.11 device entries
for IF in $(iw dev | awk '/Interface/ {print $2}'); do
  if [[ $IF =~ ^mon|^ap ]]; then
    echo "  • iw dev $IF del"
    sudo iw dev $IF del          2>/dev/null || true
  fi
done

# Create exactly two fresh interfaces:

# 1) A monitor‐mode interface "mon0"
echo "➜ Creating monitor interface mon0"
sudo iw dev wlxe84e06aed7ca interface add mon0 type monitor
sudo ip link set mon0 up

# 2) An AP‐mode interface "ap0"
echo "➜ Creating AP interface ap0"
sudo iw phy phy0 interface add ap0 type __ap
sudo ip link set ap0 up

echo
echo "✅ Done. Interfaces now:"
iw dev mon0 info
iw dev ap0 info
