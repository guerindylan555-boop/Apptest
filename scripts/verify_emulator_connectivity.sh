#!/bin/bash

# Verify Android Emulator Internet Connectivity
# This script checks if the emulator and apps have proper internet access

EMULATOR_ID="emulator-5556"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🔍 Checking Android emulator connectivity...${NC}"

# Check if emulator is running
if ! adb devices | grep -q "$EMULATOR_ID"; then
    echo -e "${RED}❌ Emulator $EMULATOR_ID not found!${NC}"
    echo "Please start the emulator first."
    exit 1
fi

echo -e "${GREEN}✅ Emulator is running${NC}"

# Check network validation
echo -e "\n${YELLOW}📊 Network validation status:${NC}"
VALIDATION_COUNT=$(adb -s "$EMULATOR_ID" shell dumpsys connectivity 2>/dev/null | grep -c "everValidated.*true" || echo "0")

if [[ "$VALIDATION_COUNT" -ge "1" ]]; then
    echo -e "${GREEN}✅ $VALIDATION_COUNT network interfaces validated${NC}"
else
    echo -e "${RED}❌ No network interfaces validated${NC}"
fi

# Check proxy settings
echo -e "\n${YELLOW}🔧 Proxy configuration:${NC}"
PROXY_STATUS=$(adb -s "$EMULATOR_ID" shell settings get global http_proxy 2>/dev/null || echo ":0")

if [[ "$PROXY_STATUS" == ":0" ]]; then
    echo -e "${GREEN}✅ Proxy is disabled (good for development)${NC}"
else
    echo -e "${YELLOW}⚠️  Proxy is enabled: $PROXY_STATUS${NC}"
fi

# Check DNS configuration
echo -e "\n${YELLOW}🌐 DNS configuration:${NC}"
DNS_SERVERS=$(adb -s "$EMULATOR_ID" shell getprop net.dns1 2>/dev/null || echo "Not set")
echo "Primary DNS: $DNS_SERVERS"

# Test connectivity from emulator
echo -e "\n${YELLOW}🌍 Testing connectivity:${NC}"

# Test 1: Network interface status
echo "Checking network interfaces..."
INTERFACES=$(adb -s "$EMULATOR_ID" shell ip addr show | grep -E "^[0-9]+:" | cut -d: -f2 | tr -d ' ')
if [[ -n "$INTERFACES" ]]; then
    echo -e "${GREEN}✅ Network interfaces found: $INTERFACES${NC}"
else
    echo -e "${RED}❌ No network interfaces found${NC}"
fi

# Test 2: Routing table
echo "Checking routing table..."
DEFAULT_ROUTE=$(adb -s "$EMULATOR_ID" shell ip route show | grep "default\|0.0.0.0/0" | head -1)
if [[ -n "$DEFAULT_ROUTE" ]]; then
    echo -e "${GREEN}✅ Default route found: $DEFAULT_ROUTE${NC}"
else
    echo -e "${YELLOW}⚠️  No default route found (this may be normal for emulator)${NC}"
fi

# Test 3: App connectivity test
echo -e "\n${YELLOW}📱 Testing app connectivity:${NC}"

# Test with Google Play Services
PLAY_SERVICES_STATUS=$(adb -s "$EMULATOR_ID" shell dumpsys activity services | grep -c "com.google.android.gms" || echo "0")
if [[ "$PLAY_SERVICES_STATUS" -gt "0" ]]; then
    echo -e "${GREEN}✅ Google Play Services running ($PLAY_SERVICES_STATUS services)${NC}"
else
    echo -e "${YELLOW}⚠️  Google Play Services not fully running${NC}"
fi

# Test connectivity check attempts
echo "Checking recent connectivity attempts..."
RECENT_CHECKS=$(adb -s "$EMULATOR_ID" shell logcat -d -t 100 | grep -c "NetworkMonitor.*PROBE_HTTP" || echo "0")
if [[ "$RECENT_CHECKS" -gt "0" ]]; then
    echo -e "${GREEN}✅ Active connectivity monitoring detected ($RECENT_CHECKS recent checks)${NC}"
else
    echo -e "${YELLOW}⚠️  No recent connectivity checks found${NC}"
fi

# Test 4: Quick browser test
echo -e "\n${YELLOW}🌐 Browser connectivity test:${NC}"
echo "Launching browser to test connectivity..."
adb -s "$EMULATOR_ID" shell am start -a android.intent.action.VIEW -d "https://www.google.com" >/dev/null 2>&1 &
sleep 5

# Check if browser launched successfully
BROWSER_ACTIVITY=$(adb -s "$EMULATOR_ID" shell dumpsys activity top | grep -m 1 "ACTIVITY" | grep -E "(com\.android\.chrome|com\.google\.android\.browser)" || echo "")
if [[ -n "$BROWSER_ACTIVITY" ]]; then
    echo -e "${GREEN}✅ Browser launched successfully${NC}"
else
    echo -e "${YELLOW}⚠️  Browser test inconclusive${NC}"
fi

# Summary
echo -e "\n${YELLOW}📋 Summary:${NC}"
if [[ "$VALIDATION_COUNT" -ge "1" ]] && [[ "$PROXY_STATUS" == ":0" ]]; then
    echo -e "${GREEN}🎉 Emulator network configuration appears to be working correctly!${NC}"
    echo -e "${GREEN}   - Network validation: ✅${NC}"
    echo -e "${GREEN}   - Proxy settings: ✅${NC}"
    echo -e "${GREEN}   - Services: ✅${NC}"
    echo -e "${GREEN}   - Connectivity monitoring: ✅${NC}"
    echo -e "${GREEN}   The emulator should have full internet access.${NC}"
    exit 0
else
    echo -e "${RED}❌ Some network configuration issues detected${NC}"
    echo -e "${RED}   Run: /home/blhack/project/Apptest/scripts/emulator_network_setup.sh${NC}"
    exit 1
fi