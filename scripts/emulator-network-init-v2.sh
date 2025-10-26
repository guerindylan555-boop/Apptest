#!/bin/bash

# Enhanced Emulator Network Initialization Script v2
# Restores and maintains internet connectivity for Android emulator

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

EMULATOR_ID=${EMULATOR_ID:-"emulator-5556"}
LOG_FILE="/tmp/emulator-network-init-v2.log"

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
            log "${GREEN}✓ Emulator is ready!${NC}"
            return 0
        fi

        attempt=$((attempt + 1))
        echo -n "."
        sleep 2
    done

    log "${RED}✗ Timeout waiting for emulator to be ready${NC}"
    return 1
}

# Function to completely reset network configuration
reset_network_configuration() {
    log "${YELLOW}Resetting network configuration...${NC}"

    # Ensure root access
    adb -s "$EMULATOR_ID" root >/dev/null 2>&1

    # Clear all network blockers
    log "Clearing network blockers..."
    adb -s "$EMULATOR_ID" shell settings put global airplane_mode_on 0

    # Clear proxy settings completely
    adb -s "$EMULATOR_ID" shell settings delete global http_proxy 2>/dev/null || true
    adb -s "$EMULATOR_ID" shell settings delete global global_http_proxy_host 2>/dev/null || true
    adb -s "$EMULATOR_ID" shell settings delete global global_http_proxy_port 2>/dev/null || true

    # Clear Private DNS settings
    adb -s "$EMULATOR_ID" shell settings put global private_dns_mode 0  # 0 = off
    adb -s "$EMULATOR_ID" shell settings delete global private_dns_specifier 2>/dev/null || true

    # Enable network services
    log "Enabling network services..."
    adb -s "$EMULATOR_ID" shell svc wifi enable
    adb -s "$EMULATOR_ID" shell svc data enable

    # Perform complete network reset
    log "Performing complete network reset..."
    adb -s "$EMULATOR_ID" shell cmd connectivity airplane-mode enable
    sleep 3
    adb -s "$EMULATOR_ID" shell cmd connectivity airplane-mode disable
    sleep 5

    # Additional network services reset
    adb -s "$EMULATOR_ID" shell svc wifi disable
    sleep 2
    adb -s "$EMULATOR_ID" shell svc wifi enable
    sleep 3
}

# Function to fix DNS configuration
fix_dns_configuration() {
    log "${YELLOW}Fixing DNS configuration...${NC}"

    # Check current DNS
    local current_dns
    current_dns=$(adb -s "$EMULATOR_ID" shell getprop net.dns1 2>/dev/null | tr -d '\r')
    log "Current DNS: $current_dns"

    # Flush DNS cache
    log "Flushing DNS cache..."
    adb -s "$EMULATOR_ID" shell ndc resolver flushdefaultif 2>/dev/null || true
    adb -s "$EMULATOR_ID" shell ndc resolver flushif wlan0 2>/dev/null || true
    adb -s "$EMULATOR_ID" shell ndc resolver flushif radio0 2>/dev/null || true

    # Set DNS to emulator's default
    adb -s "$EMULATOR_ID" shell setprop net.dns1 10.0.2.3
    adb -s "$EMULATOR_ID" shell setprop net.dns2 8.8.8.8  # backup DNS

    # Restart network services to apply DNS changes
    log "Restarting network services for DNS..."
    adb -s "$EMULATOR_ID" shell ndc network destroy 104 2>/dev/null || true  # mobile network
    adb -s "$EMULATOR_ID" shell ndc network destroy 105 2>/dev/null || true  # wifi network
    sleep 2
}

# Function to trigger network validation
trigger_network_validation() {
    log "${YELLOW}Triggering network validation...${NC}"

    # Wait for networks to stabilize
    sleep 5

    # Force Android to re-evaluate network connectivity
    log "Starting connectivity validation check..."

    # Use Android's built-in connectivity check URL
    adb -s "$EMULATOR_ID" shell am start -a android.intent.action.VIEW -d "http://connectivitycheck.gstatic.com/generate_204" 2>/dev/null || true

    # Alternative: use browser to trigger validation
    adb -s "$EMULATOR_ID" shell am start -n com.android.browser/.BrowserActivity -a android.intent.action.VIEW -d "http://connectivitycheck.gstatic.com/generate_204" 2>/dev/null || true

    # Wait for validation to complete
    log "Waiting for network validation..."
    sleep 10

    # Trigger network stack re-evaluation
    adb -s "$EMULATOR_ID" shell cmd connectivity network-request -1 CELLULAR 2>/dev/null || true
    adb -s "$EMULATOR_ID" shell cmd connectivity network-request -1 WIFI 2>/dev/null || true
}

# Function to test internet connectivity
test_connectivity() {
    log "${YELLOW}Testing network connectivity...${NC}"

    # Test basic host connectivity
    if adb -s "$EMULATOR_ID" shell ping -c 1 10.0.2.2 >/dev/null 2>&1; then
        log "${GREEN}✓ Host connectivity (10.0.2.2) OK${NC}"
    else
        log "${RED}✗ Host connectivity failed${NC}"
        return 1
    fi

    # Test DNS resolution
    local dns_server
    dns_server=$(adb -s "$EMULATOR_ID" shell getprop net.dns1 2>/dev/null | tr -d '\r')
    log "DNS server: $dns_server"

    # Test HTTP connectivity using Android's method
    log "Testing HTTP connectivity..."

    # Try to reach Android's connectivity check server
    if adb -s "$EMULATOR_ID" shell am start -a android.intent.action.VIEW -d "http://connectivitycheck.gstatic.com/generate_204" >/dev/null 2>&1; then
        log "${GREEN}✓ Connectivity check initiated${NC}"
        sleep 5
    fi

    # Try using toybox wget if available (some emulators have it)
    if adb -s "$EMULATOR_ID" shell toybox wget --help >/dev/null 2>&1; then
        log "Testing with toybox wget..."
        if adb -s "$EMULATOR_ID" shell toybox wget -q --timeout=10 -O /dev/null http://connectivitycheck.gstatic.com/generate_204 2>/dev/null; then
            log "${GREEN}✓ HTTP connectivity (wget) OK${NC}"
        else
            log "${YELLOW}⚠ HTTP connectivity (wget) failed${NC}"
        fi
    fi

    # Test with curl if available (rare on Android)
    if adb -s "$EMULATOR_ID" shell which curl >/dev/null 2>&1; then
        if adb -s "$EMULATOR_ID" shell curl -s --connect-timeout 5 http://connectivitycheck.gstatic.com/generate_204 >/dev/null 2>&1; then
            log "${GREEN}✓ HTTP connectivity (curl) OK${NC}"
        else
            log "${YELLOW}⚠ HTTP connectivity (curl) failed${NC}"
        fi
    fi

    # Check network validation status
    log "Checking network validation status..."
    adb -s "$EMULATOR_ID" shell dumpsys connectivity | grep -E "(everValidated|lastValidated)" | head -5
}

# Function to setup adb reverse for local development
setup_adb_reverse() {
    log "${YELLOW}Setting up adb reverse for local development...${NC}"

    # Reverse backend API port
    if adb -s "$EMULATOR_ID" reverse tcp:3001 tcp:3001 2>/dev/null; then
        log "${GREEN}✓ adb reverse for port 3001 (backend) configured${NC}"
    else
        log "${YELLOW}⚠ adb reverse for port 3001 failed (port might be in use)${NC}"
    fi

    # Reverse orchestrator port if needed
    if adb -s "$EMULATOR_ID" reverse tcp:8000 tcp:8000 2>/dev/null; then
        log "${GREEN}✓ adb reverse for port 8000 (orchestrator) configured${NC}"
    else
        log "${YELLOW}⚠ adb reverse for port 8000 failed (port might not be listening)${NC}"
    fi
}

# Function to create persistent network configuration
create_persistent_config() {
    log "${YELLOW}Creating persistent network configuration...${NC}"

    # Create an enhanced init script
    local init_script="/data/local/tmp/network-init-v2.sh"

    adb -s "$EMULATOR_ID" shell "cat > $init_script" << 'EOF'
#!/system/bin/sh

# Enhanced persistent network initialization
# Runs automatically after boot

LOG_TAG="NetworkInit"

# Wait for system to be fully booted
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
done

# Wait for network services to be ready
sleep 10

log -t $LOG_TAG "Starting network configuration..."

# Clear any network blockers
settings put global airplane_mode_on 0
settings delete global http_proxy 2>/dev/null || true
settings put global private_dns_mode 0

# Enable network services
svc wifi enable
svc data enable

# Wait for networks to connect
sleep 5

# Configure DNS if missing
if [ "$(getprop net.dns1)" = "" ]; then
    setprop net.dns1 10.0.2.3
    setprop net.dns2 8.8.8.8
fi

# Trigger connectivity validation
am start -a android.intent.action.VIEW -d "http://connectivitycheck.gstatic.com/generate_204" 2>/dev/null || true

log -t $LOG_TAG "Network configuration completed"
EOF

    # Make it executable
    adb -s "$EMULATOR_ID" shell chmod +x "$init_script"

    # Create a service to run it on boot (requires root)
    local rc_script="/data/local/tmp/network-init.rc"
    adb -s "$EMULATOR_ID" shell "cat > $rc_script" << 'EOF'
# Network initialization service
service network_init_v2 /system/bin/sh /data/local/tmp/network-init-v2.sh
    class main
    user root
    group root
    oneshot
    disabled
    on property:sys.boot_completed=1
    start network_init_v2
EOF

    # Mount system rw and install the service (advanced, may fail on some builds)
    adb -s "$EMULATOR_ID" shell "mount -o remount,rw /system 2>/dev/null && cp $rc_script /etc/init/network_init_v2.rc 2>/dev/null || true"

    log "Created enhanced persistent network script at $init_script"
}

# Function to show final status
show_final_status() {
    log "${BLUE}=== Final Network Status ===${NC}"

    # Show current routes
    log "Current routing table:"
    adb -s "$EMULATOR_ID" shell ip route show 2>/dev/null || echo "Unable to get routes"

    # Show DNS configuration
    log "DNS configuration:"
    adb -s "$EMULATOR_ID" shell getprop | grep dns | head -3

    # Show network validation status
    log "Network validation status:"
    adb -s "$EMULATOR_ID" shell dumpsys connectivity | grep -E "(everValidated|lastValidated|Default network)" | head -5

    # Show adb reverse status
    log "adb reverse status:"
    adb -s "$EMULATOR_ID" reverse --list 2>/dev/null || echo "No adb reverse configured"

    # Test if backend is accessible from emulator
    log "Testing backend accessibility from emulator:"
    if adb -s "$EMULATOR_ID" shell ping -c 1 10.0.2.2 >/dev/null 2>&1; then
        log "${GREEN}✓ Host machine accessible${NC}"
    else
        log "${RED}✗ Host machine not accessible${NC}"
    fi
}

# Main execution
main() {
    log "=== Enhanced Emulator Network Initialization v2 ==="
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
    reset_network_configuration || exit 1
    fix_dns_configuration || exit 1
    trigger_network_validation || exit 1
    setup_adb_reverse
    test_connectivity
    create_persistent_config
    show_final_status

    log "${GREEN}=== Enhanced network initialization completed! ===${NC}"
    log "Log saved to: $LOG_FILE"
    log "${YELLOW}If internet still doesn't work, the emulator may need to be restarted with -dns-server flag${NC}"
}

# Handle signals gracefully
trap 'log "Script interrupted"; exit 1' INT TERM

# Run main function
main "$@"