#!/usr/bin/env python3
import json
import os
import subprocess
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

ADB_HOST = os.getenv("ADB_SERVER_HOST", "127.0.0.1")
ADB_PORT = os.getenv("ADB_SERVER_PORT", "5037")
SERIAL   = os.getenv("SERIAL", "").strip()

def run(*args):
    env = os.environ.copy()
    env["ADB_SERVER_HOST"] = ADB_HOST
    env["ADB_SERVER_PORT"] = ADB_PORT
    r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    return r.returncode, r.stdout.strip(), r.stderr.strip()

def pick_emulator_serial():
    rc, out, _ = run("adb", "devices")
    if rc != 0: return ""
    for line in out.splitlines():
        m = re.match(r"^(emulator-\d+)\s+device$", line.strip())
        if m: return m.group(1)
    return ""

def ensure_serial():
    s = SERIAL or pick_emulator_serial()
    if not s:
        raise RuntimeError("No emulator device found")
    return s

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
            rc, out, err = run("adb", "devices")
            ok = rc == 0 and "emulator-" in out and "device" in out
            return self._json(200 if ok else 503, {"ok": ok, "out": out, "err": err})
        if self.path == "/status":
            try:
                s = ensure_serial()
                rc, out, err = run("adb", "-s", s, "emu", "help")
                return self._json(200 if rc == 0 else 500, {"ok": rc == 0, "serial": s, "out": out, "err": err})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/fix":
            try:
                s = ensure_serial()
                ln = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(ln) or "{}")
                lat = float(body["lat"])
                lng = float(body["lng"])
                alt = float(body.get("alt", 120.0))
                # IMPORTANT: emulator wants:  geo fix <LONG> <LAT> [ALT]
                rc, out, err = run("adb", "-s", s, "emu", "geo", "fix",
                                   f"{lng:.7f}", f"{lat:.7f}", f"{alt:.1f}")
                ok = (rc == 0) and ("OK" in (out + err))
                return self._json(200 if ok else 500, {"ok": ok, "serial": s, "out": out, "err": err})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})
        self._json(404, {"error": "not found"})

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8765), H).serve_forever()