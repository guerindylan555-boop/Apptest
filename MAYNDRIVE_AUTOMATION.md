# MaynDrive Scooter Lock/Unlock Automation

Complete automation system for MaynDrive scooter operations including lock (pause) and unlock (resume) flows with API capture capabilities.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Setup](#setup)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Troubleshooting](#troubleshooting)

---

## Overview

This project automates the lock and unlock operations for MaynDrive electric scooters by simulating UI interactions and capturing the underlying API calls using Frida dynamic instrumentation.

### Features

- ✅ **Automated Lock Flow** - Pauses/locks an active scooter rental
- ✅ **Automated Unlock Flow** - Resumes a paused scooter rental
- ✅ **API Call Interception** - Captures exact HTTP requests using Frida
- ✅ **WebRTC Stream Stability** - Fixed reconnection logic with exponential backoff
- ✅ **Comprehensive Logging** - All UI dumps and API captures saved

---

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (React)                      │
│  - WebRTC streaming of Android emulator                 │
│  - Stream reconnection with exponential backoff          │
│  - StreamViewer component                                │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                  Backend (Node.js/Express)               │
│  - Stream ticket management                              │
│  - Emulator health monitoring                            │
│  - Log aggregation                                       │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              Android Emulator (Always-On)                │
│  - MaynDrive app running                                 │
│  - ADB server (port 5037)                                │
│  - WebRTC streaming (port 9000)                          │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                  Automation Scripts                      │
│  - Lock flow automation (Node.js)                        │
│  - Unlock flow automation (Node.js)                      │
│  - UI interaction via ADB                                │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              Frida Instrumentation                       │
│  - HTTP request interception                             │
│  - API parameter capture                                 │
│  - frida-server on emulator                              │
└─────────────────────────────────────────────────────────┘
```

---

## Setup

### Prerequisites

- Android Emulator running (emulator-5556)
- ADB installed and accessible
- Frida 17.4.0+ installed
- Node.js 18+
- MaynDrive app installed on emulator

### Installation

1. **Start the Android Emulator:**
   ```bash
   # Emulator should be running on emulator-5556
   adb devices
   ```

2. **Deploy frida-server to emulator:**
   ```bash
   adb -s emulator-5556 push frida-server-17.4.0 /data/local/tmp/frida-server
   adb -s emulator-5556 shell chmod 755 /data/local/tmp/frida-server
   adb -s emulator-5556 shell "/data/local/tmp/frida-server &"
   ```

3. **Ensure MaynDrive app is logged in:**
   - User must be authenticated before running automation

---

## Usage

### Lock Flow (Pause Scooter)

**Script:** `scripts/working/mayndrive_lock_flow.js`

**Prerequisites:**
- User must be logged in
- Active scooter rental (not paused)
- Timer visible on screen

**Run:**
```bash
EMULATOR_SERIAL=emulator-5556 node scripts/working/mayndrive_lock_flow.js
```

**What it does:**
1. Verifies user is logged in
2. Checks for active scooter (TUF055)
3. Taps Info button (top right)
4. Taps "Take a break"
5. Confirms with "Pause my rent" button
6. Handles success dialog
7. Verifies scooter is paused

**Output:**
- UI dumps saved to: `var/autoapp/dumps/lock/`
- Console output with step-by-step progress

**Key Fix (2025-10-24):**
- **Fixed login detection:** Now correctly identifies logged-in state when user has active rental
- **Fixed button coordinates:** "Pause my rent" button at (540, 1524) instead of incorrect (540, 2085)

---

### Unlock Flow (Resume Scooter)

**Script:** `scripts/working/mayndrive_unlock_flow.js`

**Prerequisites:**
- User must be logged in
- Scooter must be paused (not actively riding)

**Run:**
```bash
EMULATOR_SERIAL=emulator-5556 node scripts/working/mayndrive_unlock_flow.js
```

**What it does:**
1. Verifies user session
2. Detects paused scooter
3. Taps ride controls (plus button)
4. Taps "Start to ride"
5. Confirms with "Resume my rent"
6. Handles unlock success dialog
7. Verifies ride timer active

**Output:**
- UI dumps saved to: `var/autoapp/dumps/unlock/`
- Console output with verification steps

---

### API Capture with Frida

**Capture Scripts:**
- `scripts/working/capture_lock_flow.sh` - Automated lock with API capture
- `scripts/working/capture_unlock_flow.sh` - Automated unlock with API capture

**Frida Hook Scripts:**
- `mayndrive_simple_capture.js` - Low-level HTTP request hooking (✅ **WORKS**)
- `mayndrive_enhanced_capture.js` - High-level API interface hooking (outdated)
- `mayndrive_auto_capture.js` - Dynamic method hooking

**Run with capture:**
```bash
# Lock flow with API capture
FRIDA_SCRIPT=mayndrive_simple_capture.js \
EMULATOR_SERIAL=emulator-5556 \
bash scripts/working/capture_lock_flow.sh
```

**Captured Data:**
- Lock API request → `/tmp/mayndrive_lock_capture.*.log`
- Unlock API request → `/tmp/mayndrive_unlock_capture.*.log`
- Full HTTP details including headers and body

---

## API Documentation

### 🔒 Lock API (Temporary Pause)

**Endpoint:**
```
POST https://api.knotcity.io/api/application/vehicles/freefloat/lock/temporary
```

**Headers:**
```
Authorization: Bearer {JWT_TOKEN}
Content-Type: application/json
```

**Request Body:**
```json
{
  "vehicleId": 909,
  "force": false
}
```

**cURL Example:**
```bash
curl -X POST 'https://api.knotcity.io/api/application/vehicles/freefloat/lock/temporary' \
  -H 'Authorization: Bearer YOUR_JWT_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"vehicleId": 909, "force": false}'
```

**Response:** Success with trip paused confirmation

---

### 🔓 Unlock API (Resume Trip)

**Endpoint:**
```
PUT https://api.knotcity.io/api/application/trips/{tripId}/resume
```

**Example:**
```
PUT https://api.knotcity.io/api/application/trips/321668/resume
```

**Headers:**
```
Authorization: Bearer {JWT_TOKEN}
```

**Request Body:** (empty)

**URL Parameters:**
- `{tripId}`: Active trip ID (e.g., 321668)

**cURL Example:**
```bash
curl -X PUT 'https://api.knotcity.io/api/application/trips/321668/resume' \
  -H 'Authorization: Bearer YOUR_JWT_TOKEN'
```

**Response:** Success with vehicle unlocked confirmation

---

### JWT Token Structure

The Authorization Bearer token is a JWT with:

```json
{
  "user_id": 117953,
  "session_id": "f4ef83da-21b0-4deb-b7f6-f801c7438577",
  "iat": 1761295980,
  "exp": 1761299580
}
```

- **iat** (issued at): Unix timestamp when token was created
- **exp** (expiration): Token expires 1 hour after issuance
- **session_id**: Unique session identifier
- **user_id**: MaynDrive user account ID

---

## File Structure

```
Apptest/
├── scripts/working/
│   ├── mayndrive_lock_flow.js          # Lock automation (FIXED)
│   ├── mayndrive_unlock_flow.js        # Unlock automation
│   ├── capture_lock_flow.sh            # Lock with Frida capture
│   └── capture_unlock_flow.sh          # Unlock with Frida capture
│
├── mayndrive_simple_capture.js         # HTTP hooking (WORKS)
├── mayndrive_enhanced_capture.js       # API interface hooking
├── mayndrive_auto_capture.js           # Dynamic method hooking
│
├── frontend/src/components/
│   └── StreamViewer.tsx                # WebRTC stream with reconnect fix
│
├── var/autoapp/
│   ├── dumps/lock/                     # Lock flow UI captures
│   ├── dumps/unlock/                   # Unlock flow UI captures
│   ├── captures/                       # Frida capture logs
│   └── API_CALLS.md                    # Captured API documentation
│
└── MAYNDRIVE_AUTOMATION.md             # This file
```

---

## Troubleshooting

### Emulator Not Found

**Error:** `adb: device 'emulator-5554' not found`

**Solution:**
```bash
# Check actual emulator serial
adb devices

# Use correct serial
EMULATOR_SERIAL=emulator-5556 node scripts/working/mayndrive_lock_flow.js
```

---

### Lock Script Fails - "Not logged in"

**Error:** `[failed] User is not logged in`

**Cause:** Login detection was checking for "Scan & ride" button which disappears when user has active rental

**Fixed:** Updated `isLoggedIn()` function to detect both states:
- "Scan & ride" button (no rental)
- Active scooter UI (has rental)

---

### Frida Connection Failed

**Error:** `Failed to attach: unable to connect to remote frida-server`

**Solution:**
```bash
# Restart frida-server on emulator
adb -s emulator-5556 shell pkill frida-server
adb -s emulator-5556 push frida-server-17.4.0 /data/local/tmp/frida-server
adb -s emulator-5556 shell chmod 755 /data/local/tmp/frida-server
adb -s emulator-5556 shell "/data/local/tmp/frida-server &"
```

---

### WebRTC Stream Disconnects

**Issue:** Stream constantly reconnecting every few seconds

**Fixed:** Updated `StreamViewer.tsx` with:
- Exponential backoff (1s → 2s → 4s → 8s → 16s → 30s max)
- Debouncing for rapid disconnects (2 second window)
- Smart error handling
- Connection keepalive (`poll={true}`)

**Location:** `frontend/src/components/StreamViewer.tsx`

---

### Wrong Button Coordinates

**Error:** Button tap doesn't trigger action

**Solution:** Use UI dumps to find exact button bounds:
```bash
# Dump current UI
adb -s emulator-5556 exec-out uiautomator dump /dev/tty > current_ui.xml

# Search for button by text
grep -A5 "Pause my rent" current_ui.xml

# Calculate center: (left + right) / 2, (top + bottom) / 2
```

---

## Captured API Calls Summary

**Full documentation:** `var/autoapp/API_CALLS.md`

### Lock
- **Method:** POST
- **URL:** `/api/application/vehicles/freefloat/lock/temporary`
- **Body:** `{"vehicleId": 909, "force": false}`

### Unlock
- **Method:** PUT
- **URL:** `/api/application/trips/321668/resume`
- **Body:** (empty)

Both require valid JWT Bearer token in Authorization header.

---

## Development Notes

### Recent Fixes (2025-10-24)

1. **StreamViewer Reconnection** - Fixed aggressive reconnection causing constant stream resets
2. **Lock Flow Login Detection** - Now works when user has active rental
3. **Lock Button Coordinates** - Corrected from (540, 2085) to (540, 1524)
4. **API Capture Success** - Both lock and unlock APIs fully captured

### Frida Hooking Strategy

The app uses obfuscated class names that change with updates:

- **Old method names:** `m12581n`, `m12590e` (no longer work)
- **New method names:** Single letters `a`, `b`, `c`, etc.
- **Current working approach:** Hook low-level HTTP layer via `qh.e (RunnableC3022e)`

**Best script:** `mayndrive_simple_capture.js` - hooks at HTTP request level, resilient to obfuscation changes

---

## License

This is a research/testing project for understanding app automation and API analysis.

## Author

Automated testing framework for MaynDrive app - 2025
