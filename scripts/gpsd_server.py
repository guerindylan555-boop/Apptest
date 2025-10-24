#!/usr/bin/env python3
import json
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

SERIAL = "emulator-5556"

def run(*args):
    r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return r.returncode, r.stdout.strip(), r.stderr.strip()

class H(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/health":
            rc, out, err = run("adb", "-s", SERIAL, "get-state")
            ok = (rc == 0 and "device" in out)
            return self._json(200 if ok else 500, {"ok": ok, "out": out, "err": err})
        if self.path == "/status":
            rc, out, err = run("adb", "-s", SERIAL, "emu", "help")
            return self._json(200 if rc == 0 else 500, {"ok": rc==0, "out": out, "err": err})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/fix":
            ln = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(ln) or "{}")
            lat = float(body["lat"])
            lng = float(body["lng"])
            alt = float(body.get("alt", 120.0))
            # IMPORTANT: emulator expects GEO ORDER = longitude latitude [alt]
            rc, out, err = run("adb", "-s", SERIAL, "emu", "geo", "fix",
                               f"{lng:.7f}", f"{lat:.7f}", f"{alt:.1f}")
            ok = (rc == 0 and "OK" in (out + err))
            return self._json(200 if ok else 500, {"ok": ok, "cmd": "geo fix", "out": out, "err": err})
        self._json(404, {"error": "not found"})

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8765), H).serve_forever()