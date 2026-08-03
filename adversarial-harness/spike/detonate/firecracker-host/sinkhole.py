#!/usr/bin/env python3
# T0 deception sinkhole (detonate-stage.md §5): fake DNS + catch-all TCP/HTTP so a
# payload's beacon gets an answer, inside the boundary, never real egress. Every
# callback is logged (attributable via the run marker). Minimal; T1/T2 add real
# service emulation. Args: --bind <ip> --log <file> --pidfile <file>
import argparse, socketserver, http.server, threading, os, json
ap = argparse.ArgumentParser(); ap.add_argument("--bind"); ap.add_argument("--log"); ap.add_argument("--pidfile")
a = ap.parse_args()
open(a.pidfile, "w").write(str(os.getpid()))
def rec(kind, detail):
    open(a.log, "a").write(json.dumps({"served": "T0-sinkhole", "kind": kind, "detail": detail}) + "\n")
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): rec("http", self.path); self.send_response(200); self.end_headers(); self.wfile.write(b"OK")
    def log_message(self, *a): pass
class DNS(socketserver.BaseRequestHandler):
    def handle(self):  # answer everything with the sinkhole address (catch-all)
        data, sock = self.request; rec("dns", data[12:40].hex()); sock.sendto(data[:2] + b"\x81\x80" + data[4:], self.client_address)
threading.Thread(target=lambda: socketserver.UDPServer((a.bind, 53), DNS).serve_forever(), daemon=True).start()
http.server.HTTPServer((a.bind, 80), H).serve_forever()
