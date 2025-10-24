#!/bin/bash

# Complete GPS System for Container
# This script sets up the entire GPS system inside the Docker container
# - GPS daemon
# - Self-monitoring and auto-restart
# - API interface for host communication

set -euo pipefail

EMULATOR_SERIAL="emulator-5556"
TARGET_LAT="47.3878278"
TARGET_LNG="0.6737631"
TARGET_ALT="120"
GPS_DIR="/tmp/gps_system"
MONITOR_INTERVAL=10  # Check every 10 seconds
LOG_FILE="$GPS_DIR/gps_system.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] GPS System: $*" | tee -a "$LOG_FILE"
}

wait_for_emulator() {
    log "Waiting for emulator to be ready..."
    local attempts=0
    local max_attempts=60

    while [ $attempts -lt $max_attempts ]; do
        if adb -s "$EMULATOR_SERIAL" shell getprop sys.boot_completed 2>/dev/null | grep -q "1"; then
            log "Emulator is ready!"
            return 0
        fi

        attempts=$((attempts + 1))
        sleep 2
    done

    log "ERROR: Emulator failed to boot within ${max_attempts * 2} seconds"
    return 1
}

setup_location_services() {
    log "Setting up location services..."

    # Enable location services and set high accuracy
    adb -s "$EMULATOR_SERIAL" shell 'cmd location set-location-enabled true; settings put secure location_mode 3'

    # Enable GPS and network providers
    adb -s "$EMULATOR_SERIAL" shell settings put secure location_providers_allowed +gps,network

    # Grant location permissions to common apps
    adb -s "$EMULATOR_SERIAL" shell pm grant fr.mayndrive.app android.permission.ACCESS_FINE_LOCATION
    adb -s "$EMULATOR_SERIAL" shell pm grant fr.mayndrive.app android.permission.ACCESS_COARSE_LOCATION
    adb -s "$EMULATOR_SERIAL" shell pm grant com.google.android.apps.maps android.permission.ACCESS_FINE_LOCATION
    adb -s "$EMULATOR_SERIAL" shell pm grant com.google.android.apps.maps android.permission.ACCESS_COARSE_LOCATION

    # Reset permission denials
    adb -s "$EMULATOR_SERIAL" shell appops set fr.mayndrive.app COARSE_LOCATION allow
    adb -s "$EMULATOR_SERIAL" shell appops set fr.mayndrive.app FINE_LOCATION allow

    log "Location services configured"
}

set_gps_location() {
    local lat="$1"
    local lng="$2"
    local alt="${3:-120}"

    log "Setting GPS location to: $lat, $lng, $alt"

    # Get auth token and send GPS fix
    TOKEN=$(cat /root/.emulator_console_auth_token 2>/dev/null || echo "default_token")

    # Try bash TCP connection first
    (
        echo "auth $TOKEN"
        echo "geo fix $lng $lat $alt"
        echo "quit"
    ) > /tmp/gps_commands.txt

    if command -v nc >/dev/null 2>&1; then
        cat /tmp/gps_commands.txt | nc -w 2 localhost 5556
    else
        exec 3<>/dev/tcp/localhost/5556 2>/dev/null
        if [ $? -eq 0 ]; then
            cat /tmp/gps_commands.txt >&3
            exec 3<&-
            exec 3>&-
        else
            log "ERROR: Cannot connect to emulator console"
            return 1
        fi
    fi

    rm -f /tmp/gps_commands.txt
    log "GPS location set successfully"
}

verify_gps() {
    log "Verifying GPS status..."

    # Check GPS provider status
    local gps_status=$(adb -s "$EMULATOR_SERIAL" shell dumpsys location | grep -A5 "gps provider" | head -6)

    if echo "$gps_status" | grep -q "enabled=true"; then
        log "✅ GPS is enabled and commands are being accepted"
        echo "$gps_status"
        return 0
    else
        log "❌ GPS verification failed"
        log "Status: $gps_status"
        return 1
    fi
}

create_gps_daemon() {
    cat > "$GPS_DIR/daemon.sh" <<'DAEMONEOF'
#!/bin/bash

GPS_DIR="/tmp/gps_system"
TARGET_LAT="47.3878278"
TARGET_LNG="0.6737631"
TARGET_ALT="120"
EMULATOR_SERIAL="emulator-5556"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] GPS Daemon: $*" >> "$GPS_DIR/daemon.log"
}

set_gps() {
    local lat="$1"
    local lng="$2"
    local alt="$3"

    log "Setting GPS to: $lat, $lng, $alt"

    TOKEN=$(cat /root/.emulator_console_auth_token 2>/dev/null || echo "default_token")

    (
        echo "auth $TOKEN"
        echo "geo fix $lng $lat $alt"
        echo "quit"
    ) > /tmp/gps_commands.txt

    if command -v nc >/dev/null 2>&1; then
        cat /tmp/gps_commands.txt | nc -w 2 localhost 5556
    else
        exec 3<>/dev/tcp/localhost/5556 2>/dev/null
        if [ $? -eq 0 ]; then
            cat /tmp/gps_commands.txt >&3
            exec 3<&-
            exec 3>&-
        else
            log "Failed to connect to emulator console"
        fi
    fi

    rm -f /tmp/gps_commands.txt
}

# Set initial location
set_gps "$TARGET_LAT" "$TARGET_LNG" "$TARGET_ALT"

# Main daemon loop
while true; do
    if [ -f "$GPS_DIR/update_request.txt" ]; then
        source "$GPS_DIR/update_request.txt"
        log "Real-time GPS update: $lat, $lng, $alt"
        set_gps "$lat" "$lng" "$alt" || log "Failed to update GPS"
        rm -f "$GPS_DIR/update_request.txt"

        # Update current location
        echo "lat=$lat" > "$GPS_DIR/current_location.txt"
        echo "lng=$lng" >> "$GPS_DIR/current_location.txt"
        echo "alt=$alt" >> "$GPS_DIR/current_location.txt"
    fi
    sleep 1
done
DAEMONEOF

    chmod +x "$GPS_DIR/daemon.sh"
}

create_api_server() {
    cat > "$GPS_DIR/api_server.py" <<'APIEOF'
#!/usr/bin/env python3
import http.server
import socketserver
import json
import os
import sys
from urllib.parse import urlparse, parse_qs

GPS_DIR = "/tmp/gps_system"

class GPSAPIHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "service": "gps_system"}).encode())

        elif parsed.path == '/location':
            try:
                with open(f"{GPS_DIR}/current_location.txt", 'r') as f:
                    location = {}
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            location[key] = value

                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(location).encode())
            except FileNotFoundError:
                self.send_response(404)
                self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == '/update':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))

                lat = data.get('lat')
                lng = data.get('lng')
                alt = data.get('alt', 120)

                if lat and lng:
                    # Write update request for daemon
                    with open(f"{GPS_DIR}/update_request.txt", 'w') as f:
                        f.write(f"lat={lat}\nlng={lng}\nalt={alt}\n")

                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ok", "message": "GPS update requested"}).encode())
                else:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Missing lat or lng parameters"}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

def run_api_server():
    port = 8765
    with socketserver.TCPServer(("", port), GPSAPIHandler) as httpd:
        print(f"GPS API server running on port {port}")
        httpd.serve_forever()

if __name__ == "__main__":
    run_api_server()
APIEOF

    chmod +x "$GPS_DIR/api_server.py"
}

create_system_monitor() {
    cat > "$GPS_DIR/system_monitor.sh" <<'MONITOREOF'
#!/bin/bash

GPS_DIR="/tmp/gps_system"
MONITOR_INTERVAL=15
LOG_FILE="$GPS_DIR/system_monitor.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] System Monitor: $*" >> "$LOG_FILE"
}

check_daemon_running() {
    if [ -f "$GPS_DIR/daemon.pid" ]; then
        local pid=$(cat "$GPS_DIR/daemon.pid")
        if ps -p "$pid" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

restart_daemon() {
    log "Restarting GPS daemon..."
    cd "$GPS_DIR"
    nohup ./daemon.sh > daemon.log 2>&1 &
    echo $! > daemon.pid
    log "GPS daemon restarted with PID: $!"
}

check_api_server_running() {
    if pgrep -f "api_server.py" >/dev/null; then
        return 0
    fi
    return 1
}

restart_api_server() {
    log "Restarting API server..."
    cd "$GPS_DIR"
    nohup python3 api_server.py > api_server.log 2>&1 &
    log "API server restarted"
}

# Main monitoring loop
while true; do
    # Check emulator connection
    if ! adb -s emulator-5556 shell echo "ok" >/dev/null 2>&1; then
        log "Emulator not connected, waiting..."
        sleep $MONITOR_INTERVAL
        continue
    fi

    # Check GPS daemon
    if ! check_daemon_running; then
        log "GPS daemon not running, restarting..."
        restart_daemon
    fi

    # Check API server
    if ! check_api_server_running; then
        log "API server not running, restarting..."
        restart_api_server
    fi

    sleep $MONITOR_INTERVAL
done
MONITOREOF

    chmod +x "$GPS_DIR/system_monitor.sh"
}

start_gps_system() {
    log "Starting complete GPS system inside container"

    # Setup location services
    setup_location_services

    # Set initial GPS location
    set_gps_location "$TARGET_LAT" "$TARGET_LNG" "$TARGET_ALT"

    # Verify GPS
    verify_gps

    # Create GPS directory
    mkdir -p "$GPS_DIR"

    # Create GPS daemon
    create_gps_daemon
    log "GPS daemon script created"

    # Create API server
    create_api_server
    log "API server script created"

    # Create system monitor
    create_system_monitor
    log "System monitor script created"

    # Set initial location file
    echo "lat=$TARGET_LAT" > "$GPS_DIR/current_location.txt"
    echo "lng=$TARGET_LNG" >> "$GPS_DIR/current_location.txt"
    echo "alt=$TARGET_ALT" >> "$GPS_DIR/current_location.txt"

    # Start GPS daemon
    cd "$GPS_DIR"
    nohup ./daemon.sh > daemon.log 2>&1 &
    echo $! > daemon.pid
    log "GPS daemon started (PID: $!)"

    # Start API server
    nohup python3 api_server.py > api_server.log 2>&1 &
    log "API server started"

    # Start system monitor
    nohup ./system_monitor.sh > system_monitor.log 2>&1 &
    log "System monitor started"

    log "🎉 Complete GPS system started inside container"
    log "📍 API available at http://localhost:8765"
    log "📊 Current location: $TARGET_LAT, $TARGET_LNG, $TARGET_ALT"
    log "📝 Use POST /update with JSON: {\"lat\": 48.8566, \"lng\": 2.3522, \"alt\": 100}"
}

# Main execution
start_gps_system