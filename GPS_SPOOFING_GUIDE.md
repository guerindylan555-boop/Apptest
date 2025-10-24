# GPS Location Spoofing Guide

## Overview

This guide explains how to set up GPS location spoofing on the Android emulator for MaynDrive testing. The emulator runs inside Docker and requires special authentication to control the GPS.

## Architecture

```
Host System
├── Docker Container (3c75e7304ff6)
│   ├── Android Emulator (emulator-5556)
│   │   ├── MaynDrive App
│   │   └── GPS Provider Services
│   └── Emulator Console (localhost:5556)
└── Host ADB/Frida Tools
```

## Prerequisites

- Android emulator running (emulator-5556)
- Docker container ID: `3c75e7304ff6`
- Emulator console authentication token: `v0y2z0gSoz7JAyqD`

## Step-by-Step GPS Setup

### 1. Enable Location Services

```bash
# Enable location providers and set high accuracy mode
adb -s emulator-5556 shell 'cmd location set-location-enabled true; settings put secure location_mode 3'

# Enable both GPS and network providers
adb -s emulator-5556 shell settings put secure location_providers_allowed +gps,network
```

### 2. Grant Location Permissions

```bash
# Grant fine and coarse location permissions to MaynDrive
adb -s emulator-5556 shell pm grant fr.mayndrive.app android.permission.ACCESS_FINE_LOCATION
adb -s emulator-5556 shell pm grant fr.mayndrive.app android.permission.ACCESS_COARSE_LOCATION

# Reset any permission denials
adb -s emulator-5556 shell appops set fr.mayndrive.app COARSE_LOCATION allow
adb -s emulator-5556 shell appops set fr.mayndrive.app FINE_LOCATION allow
```

### 3. Set GPS Coordinates (Single Session)

**CRITICAL**: All commands must be sent in the same console session:

```bash
# Format: longitude, latitude, altitude
printf "auth v0y2z0gSoz7JAyqD\r\ngeo fix 0.6737631 47.3878278 120\r\nquit\r\n" | nc -w 2 localhost 5556
```

**Expected Output**:
```
Android Console: Authentication required
Android Console: type 'auth <auth_token>' to authenticate
Android Console: you can find your <auth_token>' in
'/root/.emulator_console_auth_token'
OK
Android Console: type 'help' for a list of commands
OK
OK
```

### 4. Verify GPS Status

```bash
# Check GPS provider status
adb -s emulator-5556 shell dumpsys location | grep -A5 "gps provider"

# Expected output:
# gps provider:
#   last location=Location[gps 47.387827,0.673762 hAcc=5 ... alt=120.0]
#   enabled=true
#   allowed=true
```

### 5. Confirm App is Requesting Location

```bash
# Check if MaynDrive is requesting location
adb -s emulator-5556 shell dumpsys location | grep -i mayndrive

# Expected output:
# WorkSource{10155 fr.mayndrive.app}
```

## Target Coordinates

**Current Test Location**:
- **Latitude**: 47.3878278
- **Longitude**: 0.6737631
- **Altitude**: 120.0m
- **Location**: Tours, France

## Troubleshooting

### Issue: "KO: authentication token does not match"
**Solution**: The emulator runs in Docker and uses a different token
```bash
# Get the correct token from container
sudo docker exec "3c75e7304ff6" cat /root/.emulator_console_auth_token
# Update local token file
echo "TOKEN_HERE" > ~/.emulator_console_auth_token
```

### Issue: GPS provider shows `last location=null`
**Solution**: Ensure the app is actively requesting location
```bash
# Restart app and send fresh GPS fix
adb -s emulator-5556 shell am force-stop fr.mayndrive.app
adb -s emulator-5556 shell am start -n fr.mayndrive.app/city.knot.knotapp.ui.MainActivity
# Then send GPS fix
```

### Issue: Multiple console connections
**Problem**: Separate connections cause authentication failures
**Solution**: All commands must be in the same session:
```bash
# ❌ WRONG (separate connections)
echo "auth TOKEN" | nc localhost 5556
echo "geo fix ..." | nc localhost 5556

# ✅ CORRECT (single session)
printf "auth TOKEN\r\ngeo fix ...\r\nquit\r\n" | nc localhost 5556
```

## Testing GPS with Different Apps

### Google Maps
```bash
# Launch Google Maps
adb -s emulator-5556 shell am start -n com.google.android.apps.maps/com.google.android.maps.MapsActivity
# Grant permissions
adb -s emulator-5556 shell pm grant com.google.android.apps.maps android.permission.ACCESS_FINE_LOCATION
```

### MaynDrive
```bash
# Launch MaynDrive
adb -s emulator-5556 shell am start -n fr.mayndrive.app/city.knot.knotapp.ui.MainActivity
# Verify location requests
adb -s emulator-5556 shell dumpsys location | grep -i mayndrive
```

## Location Simulation (Movement)

To simulate movement and test real-time location updates:

```bash
# Send multiple coordinates
printf "auth v0y2z0gSoz7JAyqD\r\ngeo fix 0.6737631 47.3878278 120\r\ngeo fix 0.6737632 47.3878278 120\r\ngeo fix 0.6737633 47.3878278 120\r\nquit\r\n" | nc -w 4 localhost 5556
```

## Integration with Security Testing

The GPS spoofing is essential for testing MaynDrive security vulnerabilities:

1. **Geolocation Bypass Testing**: Test if API calls validate proximity
2. **Location-based Features**: Test scooter availability in different areas
3. **Route Simulation**: Test trip tracking and route validation
4. **Multi-location Testing**: Test with various coordinates

## File Locations

- **Emulator Auth Token**: `/root/.emulator_console_auth_token` (in container)
- **Host Auth Token**: `~/.emulator_console_auth_token`
- **GPS Scripts**: `/home/blhack/project/Apptest/mayndrive_gps_spoof.js`
- **Container ID**: `3c75e7304ff6`

## Dependencies

- Android SDK with emulator
- Docker running Android emulator container
- `nc` (netcat) for console communication
- ADB for Android device communication

## Quick Reference Commands

```bash
# Complete GPS setup
adb -s emulator-5556 shell 'cmd location set-location-enabled true; settings put secure location_mode 3; settings put secure location_providers_allowed +gps,network'
adb -s emulator-5556 shell 'pm grant fr.mayndrive.app android.permission.ACCESS_FINE_LOCATION; pm grant fr.mayndrive.app android.permission.ACCESS_COARSE_LOCATION'
printf "auth v0y2z0gSoz7JAyqD\r\ngeo fix 0.6737631 47.3878278 120\r\nquit\r\n" | nc -w 2 localhost 5556

# Verify working GPS
adb -s emulator-5556 shell dumpsys location | grep -A5 "gps provider"
adb -s emulator-5556 shell dumpsys location | grep -i mayndrive
```

## Notes

- GPS spoofing works independently of Firebase/Google Services
- The authentication token is container-specific and may change on restart
- Always send commands in a single console session
- MaynDrive actively requests location with 5-second intervals
- Location accuracy is set to 5 meters by default

## History

- **2025-10-24**: Initial GPS spoofing setup and documentation
- **Fixed**: Docker container authentication issues
- **Fixed**: Single-session command requirement
- **Verified**: Working with both Google Maps and MaynDrive

---

**Status**: ✅ GPS Location Spoofing Fully Operational
**Coordinates**: 47.3878278, 0.6737631 (Tours, France)
**Last Tested**: 2025-10-24