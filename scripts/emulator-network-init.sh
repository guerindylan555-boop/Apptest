#!/bin/bash

# Emulator Network Initialization Script
# Configures Android emulator networking for MaynDrive UI Mapping

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

EMULATOR_ID=${EMULATOR_ID:-"emulator-5556"}
LOG_FILE="/tmp/emulator-network-init.log"

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to check if emulator is ready
wait_for_emulator() {
    log "Waiting for emulator $EMULATOR_ID to be ready..."

    local max_attempts=60
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if adb -s "$EMULATOR_ID" shell getprop sys.boot_completed 2>/dev/null | grep -q "1"; then
            log "${GREEN}Emulator is ready!${NC}"
            return 0
        fi

        attempt=$((attempt + 1))
        echo -n "."
        sleep 2
    done

    log "${RED}Timeout waiting for emulator to be ready${NC}"
    return 1
}

# Function to configure network settings
configure_network() {
    log "${YELLOW}Configuring emulator network settings...${NC}"

    # Disable airplane mode
    log "Disabling airplane mode..."
    adb -s "$EMULATOR_ID" shell settings put global airplane_mode_on 0

    # Enable WiFi and mobile data
    log "Enabling WiFi and mobile data..."
    adb -s "$EMULATOR_ID" shell svc wifi enable
    adb -s "$EMULATOR_ID" shell svc data enable

    # Network reset to re-establish routes
    log "Performing network reset..."
    adb -s "$EMULATOR_ID" shell cmd connectivity airplane-mode enable
    sleep 2
    adb -s "$EMULATOR_ID" shell cmd connectivity airplane-mode disable
    sleep 3

    # Get root access and add default route if needed
    log "Configuring routing table..."
    adb -s "$EMULATOR_ID" root >/dev/null 2>&1

    # Check if default route exists
    if ! adb -s "$EMULATOR_ID" shell ip route show | grep -q "default via"; then
        log "Adding default route via 10.0.2.2..."
        adb -s "$EMULATOR_ID" shell ip route add default via 10.0.2.2 dev radio0
    else
        log "Default route already exists"
    fi

    # Show final routing table
    log "Current routing table:"
    adb -s "$EMULATOR_ID" shell ip route show

    # Verify DNS configuration
    local dns=$(adb -s "$EMULATOR_ID" shell getprop net.dns1 | tr -d '\r')
    log "DNS server: $dns"
}

# Function to test connectivity
test_connectivity() {
    log "${YELLOW}Testing network connectivity...${NC}"

    # Test host connectivity
    if adb -s "$EMULATOR_ID" shell ping -c 1 10.0.2.2 >/dev/null 2>&1; then
        log "${GREEN}✓ Host connectivity (10.0.2.2) OK${NC}"
    else
        log "${RED}✗ Host connectivity failed${NC}"
        return 1
    fi

    # Test DNS resolution
    if adb -s "$EMULATOR_ID" shell getprop net.dns1 | grep -q "10.0.2.3"; then
        log "${GREEN}✓ DNS configuration (10.0.2.3) OK${NC}"
    else
        log "${YELLOW}⚠ DNS might be misconfigured${NC}"
    fi

    # Test basic internet connectivity (if available)
    if adb -s "$EMULATOR_ID" shell ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log "${GREEN}✓ Internet connectivity OK${NC}"
    else
        log "${YELLOW}⚠ Internet connectivity not available (this may be expected)${NC}"
    fi

    # Test connectivity to backend API
    if adb -s "$EMULATOR_ID" shell ping -c 1 10.0.2.2 >/dev/null 2>&1; then
        log "${GREEN}✓ Can reach host machine (backend API should be accessible)${NC}"
    fi
}

# Function to show port status
show_port_status() {
    log "${YELLOW}Checking critical ports...${NC}"

    # Check listening ports on host
    local ports=(3001 8000 5555 5554)

    for port in "${ports[@]}"; do
        if ss -lntp 2>/dev/null | grep -q ":$port "; then
            log "${GREEN}✓ Port $port is listening on host${NC}"
        else
            log "${YELLOW}⚠ Port $port is not listening on host${NC}"
        fi
    done
}

# Function to create persistent network configuration
create_persistent_config() {
    log "${YELLOW}Creating persistent network configuration...${NC}"

    # Create a script that will run on emulator boot
    local init_script="/data/local/tmp/network-init.sh"

    adb -s "$EMULATOR_ID" shell "cat > $init_script" << 'EOF'
#!/system/bin/sh

# Wait for system to be fully booted
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
done

# Small delay to ensure network services are ready
sleep 5

# Configure network if default route is missing
if ! ip route show | grep -q "default via"; then
    # Try to add default route
    ip route add default via 10.0.2.2 dev radio0 2>/dev/null || \
    ip route add default via 10.0.2.2 dev wlan0 2>/dev/null
fi
EOF

    # Make it executable
    adb -s "$EMULATOR_ID" shell chmod +x "$init_script"

    log "Created persistent network script at $init_script"
}

# Main execution
main() {
    log "=== Emulator Network Initialization ==="
    log "Emulator ID: $EMULATOR_ID"

    # Check if ADB is available
    if ! command -v adb >/dev/null 2>&1; then
        log "${RED}Error: adb command not found${NC}"
        exit 1
    fi

    # Check if emulator is connected
    if ! adb devices | grep -q "$EMULATOR_ID"; then
        log "${RED}Error: Emulator $EMULATOR_ID not found${NC}"
        log "Available devices:"
        adb devices
        exit 1
    fi

    # Execute configuration steps
    wait_for_emulator || exit 1
    configure_network || exit 1
    test_connectivity
    show_port_status
    create_persistent_config

    log "${GREEN}=== Network initialization completed successfully! ===${NC}"
    log "Log saved to: $LOG_FILE"
}

# Handle signals gracefully
trap 'log "Script interrupted"; exit 1' INT TERM

# Run main function
main "$@"