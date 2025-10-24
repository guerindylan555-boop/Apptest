#!/bin/bash

# Automatic GPS Setup for Android Emulator
# This script configures GPS automatically on emulator boot

set -euo pipefail

# Configuration
EMULATOR_SERIAL="emulator-5556"
CONTAINER_ID="3c75e7304ff6"
AUTH_TOKEN="v0y2z0gSoz7JAyqD"
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

    # Send GPS fix in single session
    printf "auth %s\r\ngeo fix %s %s %s\r\nquit\r\n" "$AUTH_TOKEN" "$lng" "$lat" "$alt" | nc -w 2 localhost 5556

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

    if echo "$gps_status" | grep -q "enabled=true" && echo "$gps_status" | grep -q "last location=Location\[gps"; then
        log "✅ GPS is working"
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

    # Create a directory for GPS control files
    mkdir -p /tmp/gps_control

    # Create control file for current coordinates
    cat > /tmp/gps_control/current_location.txt <<EOF
lat=$TARGET_LAT
lng=$TARGET_LNG
alt=$TARGET_ALT
EOF

    # Start GPS daemon in background
    (
        while true; do
            if [ -f /tmp/gps_control/update_location.txt ]; then
                source /tmp/gps_control/update_location.txt
                log "Real-time GPS update: $lat, $lng, $alt"
                set_gps_location "$lat" "$lng" "$alt" || log "Failed to update GPS"
                rm -f /tmp/gps_control/update_location.txt
            fi
            sleep 1
        done
    ) &

    echo $! > /tmp/gps_control/daemon.pid
    log "GPS daemon started (PID: $(cat /tmp/gps_control/daemon.pid))"
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
        log "📝 Use /tmp/gps_control/update_location.txt to change location"

        # Instructions for real-time control
        cat <<EOF

🗺️  GPS Real-Time Control Instructions:

To change GPS location in real-time:
1. Create file: /tmp/gps_control/update_location.txt
2. Add coordinates:
   lat=48.8566
   lng=2.3522
   alt=100
3. Save the file - GPS will update automatically

Current location file: /tmp/gps_control/current_location.txt
GPS daemon PID: $(cat /tmp/gps_control/daemon.pid)

EOF
    else
        log "❌ GPS setup failed"
        exit 1
    fi
}

# Run main function
main "$@"