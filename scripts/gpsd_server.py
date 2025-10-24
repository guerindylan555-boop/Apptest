#!/usr/bin/env python3
import json, os, subprocess, re, shlex, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

ADB_HOST = os.getenv("ADB_SERVER_HOST", "127.0.0.1")
ADB_PORT = os.getenv("ADB_SERVER_PORT", "5037")
SERIAL   = os.getenv("SERIAL", "").strip()

# Global variables for continuous GPS updates
gps_thread = None
gps_running = False
current_location = {"lat": 48.8566, "lng": 2.3522, "alt": 120}  # Default: Paris

def run_adb(args, timeout=8):
    env = os.environ.copy()
    env["ADB_SERVER_HOST"] = ADB_HOST
    env["ADB_SERVER_PORT"] = ADB_PORT
    proc = subprocess.run(["adb"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, env=env, timeout=timeout)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

def has_console_token():
    home = os.path.expanduser("~")
    return os.path.isfile(os.path.join(home, ".emulator_console_auth_token"))

def geo_fix_console(serial, lat, lng, alt):
    # NOTE: order is lon lat [alt]
    args = ["-s", serial, "emu", "geo", "fix", f"{lng:.7f}", f"{lat:.7f}"]
    if alt is not None:
        args.append(f"{alt:.1f}")
    rc, out, err = run_adb(args)
    ok = (rc == 0) and ("KO:" not in out) and ("KO:" not in err)
    return ok, out, err

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

    # Automatically enable mock location settings
    run_adb(["-s", s, "shell", "settings", "put", "secure", "mock_location", "1"])
    run_adb(["-s", s, "shell", "appops", "set", "android", "android:mock_location", "allow"])

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

def continuous_gps_updater():
    """Background thread that sends GPS updates every 30 seconds"""
    global gps_running, current_location

    while gps_running:
        try:
            s = ensure_serial()
            lat, lng, alt = current_location["lat"], current_location["lng"], current_location["alt"]

            # Try console auth method first
            if has_console_token():
                ok, out, err = geo_fix_console(s, lat, lng, alt)
                if ok:
                    time.sleep(30)  # Send update every 30 seconds
                    continue

            # Fallback to cmd location if available
            if has_cmd_location(s):
                set_location_cmd(s, lat, lng, alt)
            else:
                set_location_legacy(s, lat, lng, alt)

            time.sleep(30)  # Wait 30 seconds before next update

        except Exception as e:
            print(f"GPS update error: {e}")
            time.sleep(30)  # Wait before retrying

def set_location_legacy(serial, lat, lng, alt):
    # Ensure mock location permissions are set
    run_adb(["-s", serial, "shell", "settings", "put", "secure", "mock_location", "1"])
    run_adb(["-s", serial, "shell", "appops", "set", "android", "android:mock_location", "allow"])

    # Try direct port forwarding to emulator console
    # First, set up port forwarding to the emulator's console
    rc, out, err = run_adb(["-s", serial, "forward", "tcp:5554", "tcp:5554"])
    if rc != 0:
        return False, out, f"Port forwarding failed: {err}"

    # Now try to connect to console and send geo fix command
    import socket
    try:
        # Connect to emulator console via forwarded port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", 5554))

        # Read welcome message
        welcome = sock.recv(1024).decode()

        # Try to authenticate with empty token or common defaults
        auth_tokens = ["", "emulator", "android", "default"]
        for token in auth_tokens:
            if token:
                sock.send(f"auth {token}\n".encode())
            else:
                sock.send(b"auth\n")
            response = sock.recv(1024).decode()
            if "OK" in response:
                # Authentication successful, send geo fix
                geo_cmd = f"geo fix {lng:.7f} {lat:.7f} {alt:.1f}\n"
                sock.send(geo_cmd.encode())
                geo_response = sock.recv(1024).decode()
                sock.close()

                if "OK" in geo_response or "OK" in response:
                    return True, geo_response, ""
                else:
                    return False, geo_response, "Console command failed"

        sock.close()
        return False, welcome, "Authentication failed with all tokens"

    except Exception as e:
        return False, "", f"Console connection failed: {str(e)}"

    # If console approach fails, try using settings put secure mock_location
    # combined with a simple location injection using service call
    rc, out, err = run_adb(["-s", serial, "shell", "service", "call", "location", "1",
                           f"f32 {lat:.7f}", f"f32 {lng:.7f}", f"f32 {alt:.1f}"])
    if rc == 0 and out:
        return True, out, err

    return False, out, "All location injection methods failed"

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
                    "continuous_running": gps_running,
                    "current_location": current_location,
                    "out": out, "err": err
                })
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if self.path == "/continuous/start":
            try:
                global gps_thread, gps_running
                if not gps_running:
                    gps_running = True
                    gps_thread = threading.Thread(target=continuous_gps_updater, daemon=True)
                    gps_thread.start()
                    return self._json(200, {"ok": True, "message": "Continuous GPS started"})
                else:
                    return self._json(200, {"ok": True, "message": "Continuous GPS already running"})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if self.path == "/continuous/stop":
            try:
                global gps_running
                gps_running = False
                return self._json(200, {"ok": True, "message": "Continuous GPS stopped"})
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

                # Try console auth method first
                if has_console_token():
                    ok, out, err = geo_fix_console(s, lat, lng, alt)
                    if ok:
                        return self._json(200, {"ok": True, "serial": s, "out": out, "err": err})

                # Fallback to cmd location if available
                if has_cmd_location(s):
                    ok, out, err = set_location_cmd(s, lat, lng, alt)
                else:
                    ok, out, err = set_location_legacy(s, lat, lng, alt)

                code = 200 if ok else 500
                return self._json(code, {"ok": ok, "serial": s, "out": out, "err": err})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if self.path == "/continuous/update":
            try:
                global current_location
                s = ensure_serial()
                ln = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(ln) or "{}")
                lat = float(body["lat"])
                lng = float(body["lng"])
                alt = float(body.get("alt", 120.0))

                # Update the stored location for continuous updates
                current_location = {"lat": lat, "lng": lng, "alt": alt}

                # Send the location immediately
                # Try console auth method first
                if has_console_token():
                    ok, out, err = geo_fix_console(s, lat, lng, alt)
                    if ok:
                        return self._json(200, {"ok": True, "serial": s, "out": out, "err": err, "message": "Location updated and will be sent continuously"})

                # Fallback to cmd location if available
                if has_cmd_location(s):
                    ok, out, err = set_location_cmd(s, lat, lng, alt)
                else:
                    ok, out, err = set_location_legacy(s, lat, lng, alt)

                code = 200 if ok else 500
                return self._json(code, {"ok": ok, "serial": s, "out": out, "err": err, "message": "Location updated and will be sent continuously"})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        self._json(404, {"error": "not found"})

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8765), H).serve_forever()