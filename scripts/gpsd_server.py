#!/usr/bin/env python3
import json, os, subprocess, re, shlex
from http.server import BaseHTTPRequestHandler, HTTPServer

ADB_HOST = os.getenv("ADB_SERVER_HOST", "127.0.0.1")
ADB_PORT = os.getenv("ADB_SERVER_PORT", "5037")
SERIAL   = os.getenv("SERIAL", "").strip()

def run_adb(args, timeout=8):
    env = os.environ.copy()
    env["ADB_SERVER_HOST"] = ADB_HOST
    env["ADB_SERVER_PORT"] = ADB_PORT
    proc = subprocess.run(["adb"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, env=env, timeout=timeout)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

def pick_emulator_serial():
    rc, out, _ = run_adb(["devices"])
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

def has_cmd_location(serial):
    rc, out, _ = run_adb(["-s", serial, "shell", "cmd", "location", "help"])
    return rc == 0 and "usage:" in out.lower()

def ensure_test_provider(serial, provider="gps"):
    # Add and enable test provider; ignore errors if it already exists.
    run_adb(["-s", serial, "shell", "cmd", "location", "providers", "add", "test", provider])
    run_adb(["-s", serial, "shell", "cmd", "location", "providers", "set", "test", provider, "enabled", "true"])

def set_location_cmd(serial, lat, lng, alt):
    ensure_test_provider(serial, "gps")
    # API 29/30+ supports --provider/--latitude/--longitude/--altitude
    args = ["-s", serial, "shell", "cmd", "location", "set",
            "--provider", "gps",
            "--latitude",  f"{lat:.7f}",
            "--longitude", f"{lng:.7f}"]
    if alt is not None:
        args += ["--altitude", f"{alt:.1f}"]
    rc, out, err = run_adb(args)
    ok = rc == 0 and (not err or "Error" not in err)
    return ok, out, err

def set_location_legacy(serial, lat, lng, alt):
    # Best-effort legacy fallback for older images: enable mock locations
    run_adb(["-s", serial, "shell", "settings", "put", "secure", "mock_location", "1"])
    # If you have a small companion app installed that consumes mock locations,
    # you can trigger it here. Without an app, legacy fallback may be a no-op.
    return False, "", "cmd location not available and no mock app installed"

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
            rc, out, err = run_adb(["devices"])
            ok = rc == 0 and "emulator-" in out and "device" in out
            return self._json(200 if ok else 503, {"ok": ok, "out": out, "err": err})
        if self.path == "/status":
            try:
                s = ensure_serial()
                rc, out, err = run_adb(["-s", s, "shell", "cmd", "location", "help"])
                return self._json(200, {
                    "ok": rc == 0,
                    "serial": s,
                    "supports_cmd_location": rc == 0,
                    "out": out, "err": err
                })
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
                if has_cmd_location(s):
                    ok, out, err = set_location_cmd(s, lat, lng, alt)
                else:
                    ok, out, err = set_location_legacy(s, lat, lng, alt)
                code = 200 if ok else 500
                return self._json(code, {"ok": ok, "serial": s, "out": out, "err": err})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})
        self._json(404, {"error": "not found"})

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8765), H).serve_forever()