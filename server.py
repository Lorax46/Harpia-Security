#!/usr/bin/env python3
"""Servidor simples para Harpia Security Dashboard"""

import http.server
import os
from urllib.parse import urlparse

PORT = 8082
BASE_DIR = "/home/ubuntu/harpia-security/web/dashboard"

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
                with open(file_path, "rb") as f:
                    self.wfile.write(f.read())
                return
        
        # Fallback para arquivos estáticos
        super().do_GET()
    
    def log_message(self, format, *args):
        pass  # Silencia logs

if __name__ == "__main__":
    os.chdir(BASE_DIR)
    server = http.server.HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Harpia Security rodando em http://0.0.0.0:{PORT}")
    print("Rotas disponíveis:")
    for route, file in ROUTES.items():
        print(f"  {route:<12} -> {file}")
    server.serve_forever()
