#!/usr/bin/env python3
import http.server
import os
from urllib.parse import urlparse

PORT = 8082
BASE_DIR = "/home/ubuntu/totvs-horus/web/dashboard"

ROUTES = {
    "/": "login.html",
    "/login": "login.html",
    "/dashboard": "dashboard.html",
    "/scans": "scans.html",
    "/findings": "findings.html",
    "/inventory": "inventory.html",
    "/providers": "providers.html",
    "/compliance": "compliance.html",
    "/settings": "settings.html",
}

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        
        if path in ROUTES:
            file_path = os.path.join(BASE_DIR, ROUTES[path])
            if os.path.exists(file_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                try:
                    with open(file_path, "rb") as f:
                        self.wfile.write(f.read())
                except BrokenPipeError:
                    pass
                return
        
        super().do_GET()
    
    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    os.chdir(BASE_DIR)
    server = http.server.HTTPServer(("0.0.0.0", PORT), Handler)
    server.socket.settimeout(1)
    print(f"TOTVS Horus rodando em http://0.0.0.0:{PORT}")
    server.serve_forever()
