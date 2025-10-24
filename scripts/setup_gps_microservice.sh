#!/bin/bash

# GPS Microservice Setup Script
# This script runs inside the emulator container to set up the GPS microservice

set -euo pipefail

EMULATOR_SERIAL="emulator-5554"
GPS_DIR="/opt/gpsd"
LOG_FILE="$GPS_DIR/setup.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] GPS Setup: $*" | tee -a "$LOG_FILE"
}

setup_gps_services() {
    log "Setting up GPS location services..."

    adb -s "$EMULATOR_SERIAL" shell 'cmd location set-location-enabled true; settings put secure location_mode 3' 2>/dev/null || true
    adb -s "$EMULATOR_SERIAL" shell settings put secure location_providers_allowed +gps,network 2>/dev/null || true
    adb -s "$EMULATOR_SERIAL" shell pm grant fr.mayndrive.app android.permission.ACCESS_FINE_LOCATION 2>/dev/null || true
    adb -s "$EMULATOR_SERIAL" shell pm grant fr.mayndrive.app android.permission.ACCESS_COARSE_LOCATION 2>/dev/null || true

    log "Location services configured"
}

install_python() {
    log "Checking Python installation..."

    # Check if Python is already available
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_VERSION=$(python3 --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
        log "Python $PYTHON_VERSION already available"
        return 0
    fi

    log "Installing Python 3.5 for container compatibility..."

    # Update apt sources for old Debian containers (remove unavailable repos)
    echo 'deb http://archive.debian.org/debian stretch main' > /etc/apt/sources.list
    echo 'deb http://archive.debian.org/debian stretch-backports main' >> /etc/apt/sources.list

    apt-get update -qq
    apt-get install -y python3 python3-pip procps net-tools 2>/dev/null

    log "Python 3.5 installed successfully"
}

create_gps_microservice() {
    log "Creating GPS microservice in $GPS_DIR..."

    mkdir -p "$GPS_DIR"

    cat > "$GPS_DIR/server.py" << 'EOFSERVER'
#!/usr/bin/env python3
import http.server
import socketserver
import json
import socket
import os
import sys

CONSOLE_HOST = "localhost"
CONSOLE_PORT = 5556
TOKEN_PATH = "/root/.emulator_console_auth_token"

def send_console(commands):
    try:
        token = open(TOKEN_PATH, "r").read().strip()
    except:
        token = "default"

    data = []
    try:
        with socket.create_connection((CONSOLE_HOST, CONSOLE_PORT), timeout=3) as s:
            s.settimeout(3)
            # Read banner
            s.recv(1024)

            # Authenticate
            s.sendall("auth {}\r\n".format(token).encode())
            data.append(s.recv(1024).decode(errors="ignore"))

            # Send commands
            for c in commands:
                s.sendall((c.strip() + "\r\n").encode())
                data.append(s.recv(1024).decode(errors="ignore"))

            # Quit
            s.sendall(b"quit\r\n")
    except Exception as e:
        return "Error: {}".format(str(e))

    return "\n".join(data)

class GPSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_json({"ok": True, "service": "container-gps-microservice"})
        elif self.path == "/status":
            try:
                status = send_console([])
                self.send_json({"status": "connected", "console": status[:100]})
            except Exception as e:
                self.send_json({"status": "error", "error": str(e)})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/fix":
            try:
                # Read content length
                content_length = int(self.headers.get("Content-Length", 0))

                # Read raw bytes and decode to string for Python 3.5 compatibility
                raw_body = self.rfile.read(content_length)
                body_str = raw_body.decode("utf-8")

                # Parse JSON
                data = json.loads(body_str)

                lat = data.get("lat")
                lng = data.get("lng")
                alt = data.get("alt", 120)

                if lat is None or lng is None:
                    self.send_json({"ok": False, "error": "Missing lat/lng"})
                    return

                # Validate ranges
                if not (-90 <= lat <= 90) or not (-180 <= lng <= 180):
                    self.send_json({"ok": False, "error": "Invalid coordinates"})
                    return

                # Send GPS fix command
                result = send_console(["geo fix {} {} {}".format(lng, lat, alt)])

                self.send_json({"ok": True, "result": result, "coords": [lat, lng, alt]})

            except Exception as e:
                self.send_json({"ok": False, "error": str(e)})
        else:
            self.send_response(404)
            self.end_headers()

    def send_json(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        json_bytes = json.dumps(data).encode("utf-8")
        self.wfile.write(json_bytes)

    def log_message(self, format, *args):
        print("[GPS] {}".format(format % args))

if __name__ == "__main__":
    os.chdir("/opt/gpsd")
    sys.stdout.write("Starting GPS microservice on port 8765...\n")
    sys.stdout.flush()

    # Python 3.5 compatible server creation
    httpd = socketserver.TCPServer(("", 8765), GPSHandler)
    print("[GPS] Server ready on port 8765")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[GPS] Server stopped")
        httpd.shutdown()
        httpd.server_close()
EOFSERVER

    chmod +x "$GPS_DIR/server.py"
    log "GPS microservice created"
}

start_gps_service() {
    log "Starting GPS microservice..."

    cd "$GPS_DIR"
    nohup python3 server.py > "$GPS_DIR/gps.log" 2>&1 &
    GPS_PID=$!
    echo $GPS_PID > "$GPS_DIR/gps.pid"

    log "GPS microservice started (PID: $GPS_PID) on port 8765"

    # Wait a moment for service to start
    sleep 2

    # Test the service (allow more time for startup)
    sleep 3
    if curl -s http://localhost:8765/health >/dev/null 2>&1; then
        log "✅ GPS microservice is healthy and accessible"
    else
        log "⚠️  GPS microservice health check failed, but service may be starting"
        # Don't fail the setup - service might need more time
    fi
}

main() {
    # Check if GPS is already set up
    if [ -f "$GPS_DIR/gps.pid" ] && kill -0 $(cat "$GPS_DIR/gps.pid") 2>/dev/null; then
        log "GPS microservice already running (PID: $(cat $GPS_DIR/gps.pid))"
        return 0
    fi

    log "=== Starting GPS Microservice Setup ==="

    # Setup location services
    setup_gps_services

    # Install Python if needed
    install_python

    # Create GPS microservice
    create_gps_microservice

    # Start GPS service
    start_gps_service

    log "=== GPS Microservice Setup Complete ==="
    log "Service available at: http://localhost:8765"
    log "Health endpoint: http://localhost:8765/health"
    log "Fix endpoint: http://localhost:8765/fix"
}

# Run main function
main "$@"