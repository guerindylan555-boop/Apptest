#!/bin/bash

# Android Emulator Network Configuration Script
# This script ensures proper network configuration for the Android emulator

set -e

EMULATOR_ID="emulator-5556"
LOG_FILE="/tmp/emulator_network_setup.log"

echo "[$(date)] Starting Android emulator network configuration..." | tee -a "$LOG_FILE"

# Function to wait for emulator to be ready
wait_for_emulator() {
    echo "[$(date)] Waiting for emulator to be ready..." | tee -a "$LOG_FILE"
    while ! adb -s "$EMULATOR_ID" shell getprop sys.boot_completed | grep -q "1"; do
        echo "[$(date)] Waiting for boot completion..." | tee -a "$LOG_FILE"
        sleep 5
    done
    echo "[$(date)] Emulator is ready!" | tee -a "$LOG_FILE"
    sleep 10  # Additional wait for services to start
}

# Function to configure network settings
configure_network() {
    echo "[$(date)] Configuring network settings..." | tee -a "$LOG_FILE"

    # Clear any proxy settings that might interfere
    adb -s "$EMULATOR_ID" shell settings put global http_proxy :0 2>/dev/null || true
    adb -s "$EMULATOR_ID" shell settings delete global http_proxy_host 2>/dev/null || true
    adb -s "$EMULATOR_ID" shell settings delete global http_proxy_port 2>/dev/null || true

    # Restart network services
    echo "[$(date)] Restarting network services..." | tee -a "$LOG_FILE"
    adb -s "$EMULATOR_ID" shell svc wifi disable 2>/dev/null || true
    adb -s "$EMULATOR_ID" shell svc data disable 2>/dev/null || true
    sleep 3
    adb -s "$EMULATOR_ID" shell svc wifi enable 2>/dev/null || true
    adb -s "$EMULATOR_ID" shell svc data enable 2>/dev/null || true

    # Trigger connectivity refresh
    adb -s "$EMULATOR_ID" shell am broadcast -a android.intent.action.CONNECTIVITY_CHANGE 2>/dev/null || true

    echo "[$(date)] Network configuration completed!" | tee -a "$LOG_FILE"
}

# Function to verify network connectivity
verify_connectivity() {
    echo "[$(date)] Verifying network connectivity..." | tee -a "$LOG_FILE"

    # Check network validation status
    VALIDATION=$(adb -s "$EMULATOR_ID" shell dumpsys connectivity | grep -c "everValidated.*true" || echo "0")
    echo "[$(date)] Network validation status: $VALIDATION interfaces validated" | tee -a "$LOG_FILE"

    # Check proxy is disabled
    PROXY_STATUS=$(adb -s "$EMULATOR_ID" shell settings get global http_proxy || echo ":0")
    echo "[$(date)] Proxy status: $PROXY_STATUS" | tee -a "$LOG_FILE"

    if [[ "$PROXY_STATUS" == ":0" ]] && [[ "$VALIDATION" -ge "1" ]]; then
        echo "[$(date)] ✅ Network configuration successful!" | tee -a "$LOG_FILE"
        return 0
    else
        echo "[$(date)] ❌ Network configuration failed!" | tee -a "$LOG_FILE"
        return 1
    fi
}

# Main execution
main() {
    # Check if emulator is running
    if ! adb devices | grep -q "$EMULATOR_ID"; then
        echo "[$(date)] ❌ Emulator $EMULATOR_ID not found!" | tee -a "$LOG_FILE"
        echo "Please start the emulator first." | tee -a "$LOG_FILE"
        exit 1
    fi

    wait_for_emulator
    configure_network

    # Wait a bit for settings to take effect
    sleep 10

    if verify_connectivity; then
        echo "[$(date)] 🎉 Emulator network setup completed successfully!" | tee -a "$LOG_FILE"
        echo "You can now use the emulator with full internet connectivity." | tee -a "$LOG_FILE"
    else
        echo "[$(date)] ⚠️  Network setup completed but verification failed." | tee -a "$LOG_FILE"
        echo "You may need to manually restart the emulator or check firewall settings." | tee -a "$LOG_FILE"
        exit 1
    fi
}

# Run the script
main "$@"