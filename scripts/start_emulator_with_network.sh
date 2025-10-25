#!/bin/bash

# Start Android Emulator with Proper Network Configuration
# This script starts the emulator with all necessary network settings

set -e

# Configuration
AVD_NAME="${1:-autoapp-local}"
EMULATOR_PORT="5556"
DNS_SERVERS="8.8.8.8,8.8.4.4"
LOG_FILE="/tmp/emulator_startup.log"

echo "[$(date)] Starting Android emulator with network configuration..." | tee -a "$LOG_FILE"

# Function to check if ports are available
check_ports() {
    local port=$1
    if lsof -i :$port >/dev/null 2>&1; then
        echo "[$(date)] Port $port is already in use." | tee -a "$LOG_FILE"
        return 1
    fi
    return 0
}

# Function to start emulator
start_emulator() {
    echo "[$(date)] Starting emulator with AVD: $AVD_NAME" | tee -a "$LOG_FILE"
    echo "[$(date)] Port: $EMULATOR_PORT, DNS: $DNS_SERVERS" | tee -a "$LOG_FILE"

    # Check if emulator is already running
    if adb devices | grep -q "emulator-$EMULATOR_PORT"; then
        echo "[$(date)] Emulator is already running on port $EMULATOR_PORT" | tee -a "$LOG_FILE"
        return 0
    fi

    # Start emulator with proper network settings
    emulator -avd "$AVD_NAME" \
        -port "$EMULATOR_PORT" \
        -dns-server "$DNS_SERVERS" \
        -no-proxy \
        -no-audio \
        -no-boot-anim \
        -no-window \
        -delay-adb \
        > /tmp/emulator_"$EMULATOR_PORT".log 2>&1 &

    EMULATOR_PID=$!
    echo "[$(date)] Emulator started with PID: $EMULATOR_PID" | tee -a "$LOG_FILE"
    echo "$EMULATOR_PID" > /tmp/emulator_pid_"$EMULATOR_PORT"
}

# Function to wait and configure
wait_and_configure() {
    echo "[$(date)] Waiting for emulator to fully boot..." | tee -a "$LOG_FILE"

    # Wait for device to appear
    timeout=120
    while [ $timeout -gt 0 ]; do
        if adb -s "emulator-$EMULATOR_PORT" shell getprop sys.boot_completed 2>/dev/null | grep -q "1"; then
            echo "[$(date)] Emulator boot completed!" | tee -a "$LOG_FILE"
            break
        fi
        echo "[$(date)] Waiting for boot... ($timeout seconds remaining)" | tee -a "$LOG_FILE"
        sleep 5
        timeout=$((timeout - 5))
    done

    if [ $timeout -le 0 ]; then
        echo "[$(date)] ❌ Emulator failed to boot within timeout!" | tee -a "$LOG_FILE"
        return 1
    fi

    # Additional wait for services
    sleep 15

    # Run network configuration
    echo "[$(date)] Running network configuration..." | tee -a "$LOG_FILE"
    /home/blhack/project/Apptest/scripts/emulator_network_setup.sh

    if [ $? -eq 0 ]; then
        echo "[$(date)] 🎉 Emulator startup and network configuration completed!" | tee -a "$LOG_FILE"
        echo "Emulator is ready for use on port $EMULATOR_PORT" | tee -a "$LOG_FILE"
    else
        echo "[$(date)] ⚠️  Network configuration failed, but emulator is running." | tee -a "$LOG_FILE"
    fi
}

# Function to create desktop shortcut
create_shortcut() {
    local shortcut_file="$HOME/Desktop/Start_Emacomator.desktop"
    cat > "$shortcut_file" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Start Android Emulator
Comment=Start Android emulator with network configuration
Exec=/home/blhack/project/Apptest/scripts/start_emulator_with_network.sh
Icon=applications-system
Terminal=true
Categories=Development;
EOF
    chmod +x "$shortcut_file"
    echo "[$(date)] Desktop shortcut created: $shortcut_file" | tee -a "$LOG_FILE"
}

# Main execution
main() {
    # Check prerequisites
    if ! command -v emulator >/dev/null 2>&1; then
        echo "[$(date)] ❌ Android emulator command not found!" | tee -a "$LOG_FILE"
        echo "Please ensure Android SDK is installed and emulator is in PATH." | tee -a "$LOG_FILE"
        exit 1
    fi

    # Check ports
    if ! check_ports $EMULATOR_PORT; then
        echo "[$(date)] Port $EMULATOR_PORT is in use. Please stop existing emulator or use different port." | tee -a "$LOG_FILE"
        exit 1
    fi

    # Start emulator
    start_emulator
    wait_and_configure

    # Create shortcut for future use
    create_shortcut

    echo "[$(date)] ✅ Setup complete!" | tee -a "$LOG_FILE"
    echo "Use 'adb -s emulator-$EMULATOR_PORT shell' to connect to the emulator." | tee -a "$LOG_FILE"
}

# Run the script
main "$@"