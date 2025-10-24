#!/bin/bash

# Automatic GPS Setup for Android Emulator
# This script configures GPS automatically on emulator boot

set -euo pipefail

# Configuration
EMULATOR_SERIAL="emulator-5556"
CONTAINER_ID="3c75e7304ff6"
AUTH_TOKEN="$(sudo cat /root/.emulator_console_auth_token 2>/dev/null || echo 'v0y2z0gSoz7JAyqD')"
TARGET_LAT="47.3878278"
TARGET_LNG="0.6737631"
TARGET_ALT="120"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
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
        echo -n "."
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

    # Execute GPS commands directly inside container using bash
    sudo docker exec -i "$CONTAINER_ID" bash -c "
        TOKEN=\$(cat /root/.emulator_console_auth_token 2>/dev/null || echo '$AUTH_TOKEN')
        {
            echo \"auth \$TOKEN\"
            echo \"geo fix $lng $lat $alt\"
            echo \"quit\"
        } > /tmp/gps_commands.txt
        # Use bash TCP connection if available, otherwise fallback
        if command -v nc >/dev/null 2>&1; then
            cat /tmp/gps_commands.txt | nc -w 2 localhost 5556
        else
            # Create simple TCP client using bash exec
            exec 3<>/dev/tcp/localhost/5556 2>/dev/null
            if [ \$? -eq 0 ]; then
                cat /tmp/gps_commands.txt >&3
                exec 3<&-
                exec 3>&-
            else
                echo \"ERROR: Cannot connect to emulator console\"
                exit 1
            fi
        fi
        rm -f /tmp/gps_commands.txt
    "

    if [ $? -eq 0 ]; then
        log "GPS location set successfully"
    else
        log "ERROR: Failed to set GPS location"
        return 1
    fi
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

setup_gps_daemon() {
    log "Starting GPS daemon for real-time updates..."

    # Create a directory for GPS control files on host
    mkdir -p /tmp/gps_control

    # Create control file for current coordinates on host
    cat > /tmp/gps_control/current_location.txt <<EOF
lat=$TARGET_LAT
lng=$TARGET_LNG
alt=$TARGET_ALT
EOF

    # Start GPS daemon inside Docker container
    sudo docker exec -i "$CONTAINER_ID" bash -c "
        # Create GPS control directory inside container
        mkdir -p /tmp/gps_control

        # Create daemon script inside container
        cat > /tmp/gps_control/daemon.sh <<'DAEMONEOF'
#!/bin/bash
TOKEN=\$(cat /root/.emulator_console_auth_token 2>/dev/null || echo '$AUTH_TOKEN')
LAT='$TARGET_LAT'
LNG='$TARGET_LNG'
ALT='$TARGET_ALT'

log() {
    echo \"[\$(date '+%Y-%m-%d %H:%M:%S')] \$*\" >&2
}

set_gps() {
    local lat=\$1
    local lng=\$2
    local alt=\$3

    log \"Setting GPS to: \$lat, \$lng, \$alt\"
    {
        echo \"auth \$TOKEN\"
        echo \"geo fix \$lng \$lat \$alt\"
        echo \"quit\"
    } > /tmp/gps_commands.txt

    # Try netcat first, then bash TCP
    if command -v nc >/dev/null 2>&1; then
        cat /tmp/gps_commands.txt | nc -w 2 localhost 5556
    else
        exec 3<>/dev/tcp/localhost/5556 2>/dev/null
        if [ \$? -eq 0 ]; then
            cat /tmp/gps_commands.txt >&3
            exec 3<&-
            exec 3>&-
        fi
    fi
    rm -f /tmp/gps_commands.txt
}

# Main daemon loop
while true; do
    if [ -f /tmp/gps_control/update_location.txt ]; then
        source /tmp/gps_control/update_location.txt
        log \"Real-time GPS update: \$lat, \$lng, \$alt\"
        set_gps \"\$lat\" \"\$lng\" \"\$alt\" || log \"Failed to update GPS\"
        rm -f /tmp/gps_control/update_location.txt

        # Update current location
        echo \"lat=\$lat\" > /tmp/gps_control/current_location.txt
        echo \"lng=\$lng\" >> /tmp/gps_control/current_location.txt
        echo \"alt=\$alt\" >> /tmp/gps_control/current_location.txt
    fi
    sleep 1
done
DAEMONEOF

        chmod +x /tmp/gps_control/daemon.sh

        # Set initial location
        echo \"lat=$TARGET_LAT\" > /tmp/gps_control/current_location.txt
        echo \"lng=$TARGET_LNG\" >> /tmp/gps_control/current_location.txt
        echo \"alt=$TARGET_ALT\" >> /tmp/gps_control/current_location.txt

        # Start daemon in background inside container
        nohup /tmp/gps_control/daemon.sh > /tmp/gps_control/daemon.log 2>&1 &
        echo \$! > /tmp/gps_control/daemon.pid
        echo \"GPS daemon started inside container (PID: \$(cat /tmp/gps_control/daemon.pid))\"
    "

    # Create a bridge script on host to communicate with container daemon
    cat > /tmp/gps_control/host_bridge.sh <<'BRIDGEEOF'
#!/bin/bash
update_location() {
    local lat="$1"
    local lng="$2"
    local alt="$3"

    echo "lat=$lat" > /tmp/gps_control/update_location.txt
    echo "lng=$lng" >> /tmp/gps_control/update_location.txt
    echo "alt=$alt" >> /tmp/gps_control/update_location.txt

    # Copy update file to container
    sudo docker exec -i "3c75e7304ff6" bash -c "cat > /tmp/gps_control/update_location.txt" < /tmp/gps_control/update_location.txt
}

# Bridge function for external API calls
if [ "${1:-}" = "update" ] && [ -n "${2:-}" ] && [ -n "${3:-}" ]; then
    update_location "$2" "$3" "${4:-120}"
fi
BRIDGEEOF

    chmod +x /tmp/gps_control/host_bridge.sh
    log "GPS daemon started inside container with host bridge"
    log "📍 Current location: $TARGET_LAT, $TARGET_LNG, $TARGET_ALT"
    log "🔧 Real-time GPS control is active"
    log "📝 Use /tmp/gps_control/host_bridge.sh to change location"
}

main() {
    log "🚀 Starting automatic GPS setup for Android emulator"

    # Wait for emulator to be ready
    wait_for_emulator

    # Setup location services
    setup_location_services

    # Set initial GPS location
    set_gps_location "$TARGET_LAT" "$TARGET_LNG" "$TARGET_ALT"

    # Verify GPS is working
    if verify_gps; then
        log "🎉 GPS setup completed successfully!"

        # Start GPS daemon for real-time updates
        setup_gps_daemon

        log "📍 Current location: $TARGET_LAT, $TARGET_LNG, $TARGET_ALT"
        log "🔧 Real-time GPS control is active"
        log "📝 Use /tmp/gps_control/host_bridge.sh to change location"

        # Instructions for real-time control
        cat <<EOF

🗺️  GPS Real-Time Control Instructions:

GPS daemon is running inside Docker container with host bridge.

To change GPS location in real-time:
1. Use bridge script: /tmp/gps_control/host_bridge.sh update 48.8566 2.3522 100
2. Or create file: /tmp/gps_control/update_location.txt with:
   lat=48.8566
   lng=2.3522
   alt=100

Container daemon logs: sudo docker exec -i $CONTAINER_ID cat /tmp/gps_control/daemon.log
Container daemon PID: \$(sudo docker exec -i $CONTAINER_ID cat /tmp/gps_control/daemon.pid 2>/dev/null || echo 'Unknown')

EOF
    else
        log "❌ GPS setup failed"
        exit 1
    fi
}

# Run main function
main "$@"