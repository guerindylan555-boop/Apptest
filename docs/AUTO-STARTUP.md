# Auto-Startup Automation

This document describes the automatic startup automation system that runs when the emulator boots.

## Overview

The auto-startup system automatically performs the following tasks when the emulator starts:

1. **Certificate Installation** - Installs mitmproxy CA certificate as a system certificate
2. **App Installation** - Extracts and installs XAPK files from the library
3. **Proxy Configuration** - Sets up HTTP proxy and starts traffic capture
4. **App Launch** - Launches the first installed app automatically
5. **Logging** - Logs all automation activities to files

## Components

### Backend Services

- **`autoStartup.ts`** - Main automation service
  - Handles certificate installation
  - Extracts and installs XAPK files
  - Configures proxy and starts capture
  - Manages logging

- **`emulatorLifecycle.ts`** - Triggers automation after boot

### API Endpoints

- **`GET /automation/logs/startup`** - View auto-startup logs
- **`GET /automation/logs/proxy`** - View proxy capture logs

## File Locations

### APK/XAPK Files
Place XAPK files in: `var/autoapp/apps/library/`

Example:
```
var/autoapp/apps/library/
  └── Mayn Drive_1.1.34.xapk
```

### Log Files
- **Startup Log**: `var/autoapp/apps/logs/auto-startup.log`
- **Proxy Capture**: `var/autoapp/apps/logs/proxy-capture.log`

## How It Works

### 1. Certificate Installation

When the emulator boots, the system:
1. Checks for mitmproxy certificate at `/root/.mitmproxy/mitmproxy-ca-cert.pem`
2. Generates certificate if not found (by running mitmdump briefly)
3. Converts certificate to Android format (hash-based filename)
4. Pushes certificate to `/system/etc/security/cacerts/` on emulator
5. Sets proper permissions (644)
6. Reboots emulator to activate certificate

### 2. XAPK Installation

The system scans `var/autoapp/apps/library/` for `.xapk` files and:
1. Extracts XAPK (which is a ZIP archive)
2. Finds all APK files inside (base + splits)
3. Installs each APK using `adb install -r`
4. Extracts package name from manifest
5. Logs installation details

### 3. Proxy Capture

After installation:
1. Configures emulator HTTP proxy: `localhost:8080`
2. Starts mitmproxy in background
3. Captures all HTTP(S) traffic to log file
4. Saves traffic flows for later analysis

### 4. App Launch

Finally:
1. Gets the first installed package name
2. Resolves main activity
3. Launches app using `am start`

## Viewing Logs

### Via API

```bash
# View startup logs
curl http://localhost:3001/automation/logs/startup

# View proxy capture logs
curl http://localhost:3001/automation/logs/proxy
```

### Via File System

```bash
# Startup logs
cat var/autoapp/apps/logs/auto-startup.log

# Proxy capture
cat var/autoapp/apps/logs/proxy-capture.log
```

## Required Tools

The backend Docker container includes:
- **unzip** - Extract XAPK files
- **aapt** - Android Asset Packaging Tool (read APK manifests)
- **mitmproxy** - HTTP(S) proxy and traffic capture
- **openssl** - Certificate conversion
- **python3** - mitmproxy dependency

## Troubleshooting

### Certificate Installation Fails
- Check emulator has root access
- Verify `/system` partition can be remounted
- Check mitmproxy is installed

### XAPK Installation Fails
- Verify XAPK file is valid ZIP archive
- Check APK files exist inside XAPK
- Ensure emulator has enough storage

### Proxy Not Capturing
- Verify mitmproxy is running
- Check proxy settings on emulator
- Look for port 8080 conflicts

### App Won't Launch
- Check package name extraction
- Verify app has main activity
- Review logcat for app errors

## Disabling Automation

To disable auto-startup automation, set environment variable:

```bash
EXTERNAL_EMULATOR=true
```

This tells the system an external emulator is running and skips automation.

## Manual Execution

To manually run automation (for testing):

```typescript
import { runStartupAutomation } from './services/autoStartup';

await runStartupAutomation();
```

## Security Considerations

- **CA Certificate**: Installing a CA certificate allows traffic interception
- **Proxy Capture**: All HTTP(S) traffic is logged (including sensitive data)
- **Root Access**: Emulator needs root for certificate installation
- **Log Files**: Contain potentially sensitive information

⚠️ **Only use in development/testing environments!**
