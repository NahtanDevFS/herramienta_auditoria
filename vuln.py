# guarda como vuln.py y corre: python3 vuln.py
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import sqlite3
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        p = urlparse(self.path); params = parse_qs(p.query)
        if p.path=="/user" and "id" in params:
            db=sqlite3.connect(":memory:")
            db.execute("CREATE TABLE users(id INT,nombre TEXT)")
            db.execute("INSERT INTO users VALUES(1,'admin')")
            try:
                r=db.execute("SELECT nombre FROM users WHERE id="+params["id"][0]).fetchall()
                self.send_response(200); self.end_headers()
                self.wfile.write(str(r).encode())
            except Exception as e:
                self.send_response(500); self.end_headers(); self.wfile.write(str(e).encode())
        else:
            self.send_response(200); self.end_headers(); self.wfile.write(b"/user?id=1")
    def log_message(self,*a): pass
HTTPServer(("127.0.0.1",8094),H).serve_forever()