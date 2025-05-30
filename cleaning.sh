# This script is used to clean up the network configuration and stop services related to hostapd and dnsmasq.
sudo pkill hostapd
sudo pkill dnsmasq
sudo systemctl restart NetworkManager