#!/bin/bash

# Simple Container-Based GPS System
# Runs everything inside container with port forwarding for API access

set -euo pipefail

EMULATOR_SERIAL="emulator-5556"
TARGET_LAT="47.3878278"
TARGET_LNG="0.6737631"
TARGET_ALT="120"
GPS_DIR="/tmp/gps_simple"
LOG_FILE="$GPS_DIR/gps.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] GPS: $*" | tee -a "$LOG_FILE"
}

setup_location_services() {
    log "Setting up location services..."

    adb -s "$EMULATOR_SERIAL" shell 'cmd location set-location-enabled true; settings put secure location_mode 3'
    adb -s "$EMULATOR_SERIAL" shell settings put secure location_providers_allowed +gps,network
    adb -s "$EMULATOR_SERIAL" shell pm grant fr.mayndrive.app android.permission.ACCESS_FINE_LOCATION
    adb -s "$EMULATOR_SERIAL" shell pm grant fr.mayndrive.app android.permission.ACCESS_COARSE_LOCATION

    log "Location services configured"
}

set_gps_location() {
    local lat="$1"
    local lng="$2"
    local alt="${3:-120}"

    log "Setting GPS to: $lat, $lng, $alt"

    TOKEN=$(cat /root/.emulator_console_auth_token 2>/dev/null || echo "default")

    # Use bash TCP connection
    (
        echo "auth $TOKEN"
        echo "geo fix $lng $lat $alt"
        echo "quit"
    ) | nc -w 2 localhost 5556 2>/dev/null || (
        # Fallback to bash TCP
        exec 3<>/dev/tcp/localhost/5556 2>/dev/null
        if [ $? -eq 0 ]; then
            (
                echo "auth $TOKEN"
                echo "geo fix $lng $lat $alt"
                echo "quit"
            ) >&3
            exec 3<&-
            exec 3>&-
        fi
    )

    log "GPS location set"
}

create_gps_daemon() {
    cat > "$GPS_DIR/gps_daemon.sh" <<'DAEMONEOF'
#!/bin/bash

EMULATOR_SERIAL="emulator-5556"
GPS_DIR="/tmp/gps_simple"
LOG_FILE="$GPS_DIR/daemon.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Daemon: $*" >> "$LOG_FILE"
}

set_gps() {
    local lat="$1"
    local lng="$2"
    local alt="$3"

    log "Setting GPS: $lat, $lng, $alt"

    TOKEN=$(cat /root/.emulator_console_auth_token 2>/dev/null || echo "default")

    (
        echo "auth $TOKEN"
        echo "geo fix $lng $lat $alt"
        echo "quit"
    ) | nc -w 2 localhost 5556 2>/dev/null || (
        exec 3<>/dev/tcp/localhost/5556 2>/dev/null
        if [ $? -eq 0 ]; then
            (
                echo "auth $TOKEN"
                echo "geo fix $lng $lat $alt"
                echo "quit"
            ) >&3
            exec 3<&-
            exec 3>&-
        fi
    )
}

# Main loop
while true; do
    if [ -f "$GPS_DIR/update.txt" ]; then
        source "$GPS_DIR/update.txt"
        log "Update: $lat, $lng, $alt"
        set_gps "$lat" "$lng" "$alt"
        rm -f "$GPS_DIR/update.txt"

        # Update current location
        echo "lat=$lat" > "$GPS_DIR/current.txt"
        echo "lng=$lng" >> "$GPS_DIR/current.txt"
        echo "alt=$alt" >> "$GPS_DIR/current.txt"
    fi
    sleep 1
done
DAEMONEOF

    chmod +x "$GPS_DIR/gps_daemon.sh"
}

create_api_server() {
    cat > "$GPS_DIR/api_server.py" <<'APIEOF'
#!/usr/bin/env python3
import http.server
import socketserver
import json
import os
from urllib.parse import urlparse

GPS_DIR = "/tmp/gps_simple"

class GPSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_json({"status": "ok", "service": "container_gps"})
        elif self.path == '/location':
            try:
                with open(f"{GPS_DIR}/current.txt", 'r') as f:
                    lines = f.readlines()
                    location = {}
                    for line in lines:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            location[key] = value
                self.send_json(location)
            except:
                self.send_response(404)
        else:
            self.send_response(404)

    def do_POST(self):
        if self.path == '/update':
            try:
                content_length = int(self.headers['Content-Length'])
                data = json.loads(self.rfile.read(content_length).decode('utf-8'))

                lat = data.get('lat')
                lng = data.get('lng')
                alt = data.get('alt', 120)

                if lat and lng:
                    with open(f"{GPS_DIR}/update.txt", 'w') as f:
                        f.write(f"lat={lat}\nlng={lng}\nalt={alt}\n")
                    self.send_json({"status": "ok"})
                else:
                    self.send_response(400)
            except:
                self.send_response(500)
        else:
            self.send_response(404)

    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

if __name__ == "__main__":
    with socketserver.TCPServer(("", 8765), GPSHandler) as httpd:
        print("GPS API server running on port 8765")
        httpd.serve_forever()
APIEOF

    chmod +x "$GPS_DIR/api_server.py"
}

create_monitor() {
    cat > "$GPS_DIR/monitor.sh" <<'MONITOREOF'
#!/bin/bash

GPS_DIR="/tmp/gps_simple"
EMULATOR_SERIAL="emulator-5556"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Monitor: $*" >> "$GPS_DIR/monitor.log"
}

# Check and restart services
while true; do
    # Check emulator
    if ! adb -s "$EMULATOR_SERIAL" shell echo "ok" >/dev/null 2>&1; then
        log "Emulator not connected"
        sleep 30
        continue
    fi

    # Check daemon
    if ! pgrep -f "gps_daemon.sh" >/dev/null; then
        log "Restarting daemon"
        cd "$GPS_DIR"
        nohup ./gps_daemon.sh > daemon.log 2>&1 &
    fi

    # Check API server
    if ! pgrep -f "api_server.py" >/dev/null; then
        log "Restarting API server"
        cd "$GPS_DIR"
        nohup python3 api_server.py > api.log 2>&1 &
    fi

    sleep 30
done
MONITOREOF

    chmod +x "$GPS_DIR/monitor.sh"
}

start_system() {
    log "Starting container GPS system"

    # Setup location services
    setup_location_services

    # Set initial location
    set_gps_location "$TARGET_LAT" "$TARGET_LNG" "$TARGET_ALT"

    # Create directory
    mkdir -p "$GPS_DIR"

    # Create scripts
    create_gps_daemon
    create_api_server
    create_monitor

    # Set initial location file
    echo "lat=$TARGET_LAT" > "$GPS_DIR/current.txt"
    echo "lng=$TARGET_LNG" >> "$GPS_DIR/current.txt"
    echo "alt=$TARGET_ALT" >> "$GPS_DIR/current.txt"

    # Start services
    cd "$GPS_DIR"
    nohup ./gps_daemon.sh > daemon.log 2>&1 &
    nohup python3 api_server.py > api.log 2>&1 &
    nohup ./monitor.sh > monitor.log 2>&1 &

    log "GPS system started - API on port 8765"
}

start_system