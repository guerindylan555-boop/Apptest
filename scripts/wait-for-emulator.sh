#!/bin/bash

# Wait for Android emulator to be ready for ADB commands
# Used by Docker containers to synchronize startup

set -e

EMULATOR_ID=${EMULATOR_ID:-"emulator-5556"}
TIMEOUT=${TIMEOUT:-180}  # 3 minutes max

echo "Waiting for emulator $EMULATOR_ID to be ready..."

# Function to check if emulator is booted
is_emulator_ready() {
    # Check if device is visible via adb
    if ! adb devices | grep -q "$EMULATOR_ID"; then
        return 1
    fi

    # Check if boot is completed
    local boot_status
    boot_status=$(adb -s "$EMULATOR_ID" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')

    [ "$boot_status" = "1" ]
}

# Wait for emulator with timeout
start_time=$(date +%s)
while true; do
    if is_emulator_ready; then
        echo "✓ Emulator $EMULATOR_ID is ready!"

        # Additional checks
        echo "Checking emulator services..."

        # Wait a bit more for system services to be ready
        sleep 5

        # Check package manager is ready
        if adb -s "$EMULATOR_ID" shell pm path android >/dev/null 2>&1; then
            echo "✓ Package manager is ready"
        else
            echo "⚠ Package manager not yet ready, waiting..."
            sleep 5
        fi

        # Verify basic connectivity
        if adb -s "$EMULATOR_ID" shell ping -c 1 10.0.2.2 >/dev/null 2>&1; then
            echo "✓ Host connectivity verified"
        else
            echo "⚠ Host connectivity not available yet"
        fi

        break
    fi

    # Check timeout
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))

    if [ $elapsed -ge $TIMEOUT ]; then
        echo "✗ Timeout waiting for emulator (waited ${TIMEOUT}s)"
        echo "Emulator status:"
        adb devices || true
        echo "Boot progress:"
        adb -s "$EMULATOR_ID" shell getprop init.svc.bootanim 2>/dev/null || true
        exit 1
    fi

    # Progress indicator
    echo -n "."
    sleep 2
done

echo "Emulator initialization completed successfully!"
echo "Device ID: $EMULATOR_ID"
echo "Emulator IP: $(adb -s "$EMULATOR_ID" shell ip route show 0.0.0.0 | awk '{print $9}' | tr -d '\r' || echo 'unknown')"