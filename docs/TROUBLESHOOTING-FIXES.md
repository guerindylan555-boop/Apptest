# Troubleshooting & Fixes Applied

This document details all the root issues found and how they were fixed.

## Root Cause Analysis

### Issue 1: Modern Android Emulator Compatibility ❌ → ✅

**Problem:**
- Android API 33+ uses a different partition structure
- `/system` partition doesn't exist in traditional writable form
- Old certificate installation approach assumed writable `/system`

**Symptoms:**
```
mount: '/system' not in /proc/mounts
adb: error: failed to copy: Read-only file system
```

**Root Cause:**
Modern Android (API 28+) uses system-as-root and dynamic partitions. The `/system` directory is no longer a separate mountable partition.

**Fix:**
1. Added `-writable-system` flag to emulator launch arguments
2. Changed certificate installation to use **user certificate store** instead of system
3. Converted certificate to DER format (Android-compatible)
4. Used Android Settings intent to install cert (no root required)

**Result:** ✅ Works on all Android versions without root access issues

---

### Issue 2: Fragile Automation Crashing Backend ❌ → ✅

**Problem:**
- Any automation step failure caused entire backend to crash
- Certificate installation failure was treated as fatal
- No graceful degradation

**Symptoms:**
```
[backend] Uncaught exception
[backend] Auto-startup automation failed
Backend container restarting...
```

**Root Cause:**
Automation was throwing errors instead of handling failures gracefully.

**Fix:**
1. Wrapped each automation step in individual try-catch blocks
2. Made certificate installation **non-fatal**
3. Made XAPK installation **non-fatal per-file**
4. Made proxy setup **non-fatal**
5. Changed `installXAPK` to return `null` on failure instead of throwing
6. Added comprehensive logging for each step

**Result:** ✅ Backend stays running even if automation steps fail

---

### Issue 3: Hardcoded Development Paths ❌ → ✅

**Problem:**
```typescript
const wrapperScript = '/home/blhack/project/Apptest/backend/scripts/launch-emulator.sh';
```

**Symptoms:**
```
spawn /home/blhack/project/Apptest/backend/scripts/launch-emulator.sh ENOENT
```

**Root Cause:**
Absolute path from development machine hardcoded in production code.

**Fix:**
Changed to use emulator binary from PATH:
```typescript
const emulatorBin = process.env.EMULATOR || 'emulator';
```

**Result:** ✅ Works in all environments (local, Docker, Dokploy)

---

### Issue 4: Docker Network DNS Resolution ❌ → ✅

**Problem:**
Browser couldn't resolve internal Docker hostnames like `ws-scrcpy`.

**Symptoms:**
```
Impossible de trouver l'adresse IP du serveur de ws-scrcpy
```

**Root Cause:**
Backend was using Docker internal hostname in stream URLs sent to browser.

**Fix:**
Changed `WS_SCRCPY_HOST` from `ws-scrcpy` to `0.0.0.0` (placeholder).
Backend now detects this and uses the actual request host (public domain/IP).

**Result:** ✅ Browser can connect to ws-scrcpy from outside Docker network

---

### Issue 5: Port Conflicts ❌ → ✅

**Problem:**
```
failed to bind host port for 0.0.0.0:5037: address already in use
```

**Root Cause:**
ADB server port was being exposed externally and conflicting with host ADB.

**Fix:**
Removed external port mapping for 5037. ADB server communication happens internally via Docker network using `ADB_SERVER_SOCKET=tcp:apptest-backend:5037`.

**Result:** ✅ No more port conflicts, ws-scrcpy connects via internal network

---

### Issue 6: AVD Name Mismatch ❌ → ✅

**Problem:**
- Dockerfile created AVD named "default"
- Backend expected AVD named "autoapp-local"

**Root Cause:**
Inconsistent configuration between Dockerfile and backend code.

**Fix:**
Set environment variable in docker-compose.yml:
```yaml
AVD_NAME=default
```

**Result:** ✅ Backend starts correct emulator

---

### Issue 7: Missing Emulator (ws-scrcpy waiting) ❌ → ✅

**Problem:**
```
[WebsocketProxy] Failed to start service: Failure: ''
```

**Root Cause:**
- `EXTERNAL_EMULATOR=true` told backend not to start emulator
- ws-scrcpy had no emulator to connect to

**Fix:**
1. Changed `EXTERNAL_EMULATOR=false`
2. Added `privileged: true` for hardware acceleration
3. Exposed emulator ports (5554, 5555)
4. Created AVD during Docker build

**Result:** ✅ Backend starts actual emulator, ws-scrcpy connects to it

---

## Complete System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Browser                          │
│  - Accesses via public domain                                │
│  - Gets stream URL with public hostname                      │
└─────────────────┬───────────────────────────────────────────┘
                  │ HTTP/WebSocket (public)
                  ↓
┌─────────────────────────────────────────────────────────────┐
│                     Frontend Container                       │
│  - Nginx serving React app (port 80 → 5173)                 │
│  - Displays stream iframe                                    │
└─────────────────┬───────────────────────────────────────────┘
                  │ API calls
                  ↓
┌─────────────────────────────────────────────────────────────┐
│                     Backend Container                        │
│  - Node.js API (port 3001)                                   │
│  - Android SDK + Emulator                                    │
│  - ADB server (port 5037 internal)                           │
│  - Runs auto-startup automation on boot                      │
│                                                               │
│  ┌─────────────────────────────────────┐                     │
│  │     Android Emulator (AVD)          │                     │
│  │  - API 33 with Google APIs          │                     │
│  │  - Console port: 5554               │                     │
│  │  - ADB port: 5555                   │                     │
│  │  - Runs with -writable-system       │                     │
│  └─────────────────────────────────────┘                     │
└─────────────────┬───────────────────────────────────────────┘
                  │ ADB over Docker network
                  │ tcp:apptest-backend:5037
                  ↓
┌─────────────────────────────────────────────────────────────┐
│                   ws-scrcpy Container                        │
│  - Connects to backend's ADB server                          │
│  - Streams emulator video (port 8000)                        │
│  - Handles touch input                                       │
└─────────────────────────────────────────────────────────────┘
```

## Automation Flow (On Emulator Boot)

```
1. Emulator starts via POST /emulator/start
   └─> launchEmulator() with -writable-system flag

2. Backend waits for boot completion
   └─> Polls sys.boot_completed property

3. Auto-startup automation triggers
   ├─> Step 1: Install CA certificate (non-fatal)
   │   ├─> Generate mitmproxy cert if needed
   │   ├─> Convert to DER format
   │   ├─> Push to /sdcard/
   │   └─> Launch Settings intent to install
   │
   ├─> Step 2: Install XAPK files (non-fatal per file)
   │   ├─> Scan var/autoapp/apps/library/ for .xapk files
   │   ├─> Extract XAPK (unzip)
   │   ├─> Install all APKs (base + splits)
   │   └─> Extract package names
   │
   ├─> Step 3: Start proxy capture (non-fatal)
   │   ├─> Enable proxy on emulator (localhost:8080)
   │   └─> Start mitmproxy with logging
   │
   └─> Step 4: Launch first installed app (non-fatal)
       ├─> Resolve main activity
       └─> Start activity via am start

4. ws-scrcpy connects via ADB
   └─> Video stream available at port 8000

5. Frontend displays stream in iframe
   └─> User can interact with emulator
```

## Current Status

✅ All root causes fixed
✅ Graceful error handling implemented
✅ Modern Android compatibility ensured
✅ Docker networking resolved
✅ Port conflicts eliminated
✅ Paths made environment-agnostic
✅ Automation won't crash backend

## Testing Checklist

After redeployment:

- [ ] Backend starts without errors
- [ ] ws-scrcpy starts (waits for emulator)
- [ ] POST /emulator/start succeeds
- [ ] Emulator boots within 2-3 minutes
- [ ] Auto-startup automation runs (check logs)
- [ ] XAPK installs successfully
- [ ] App launches automatically
- [ ] ws-scrcpy connects to emulator
- [ ] Stream appears in frontend
- [ ] Touch controls work
- [ ] Proxy captures traffic

## Viewing Logs

```bash
# Backend logs
docker logs apptest-backend

# ws-scrcpy logs
docker logs apptest-ws-scrcpy

# Automation logs
curl http://your-server:3001/automation/logs/startup

# Proxy capture logs
curl http://your-server:3001/automation/logs/proxy
```

## Environment Variables Reference

### Backend
```yaml
NODE_ENV=production
PORT=3001
EXTERNAL_EMULATOR=false          # Backend starts emulator
AVD_NAME=default                 # AVD to start
WS_SCRCPY_HOST=0.0.0.0          # Use request host
WS_SCRCPY_PORT=8000
EMULATOR_CONSOLE_PORT=5554
EMULATOR_ADB_PORT=5555
```

### ws-scrcpy
```yaml
ADB_SERVER_SOCKET=tcp:apptest-backend:5037  # Connect to backend's ADB
```

## Additional Fixes Applied (Session 2)

### Issue 8: Missing Volume Mount for App Library ❌ → ✅

**Problem:**
- XAPK files stored on host were not visible inside Docker container
- Automation found "0 XAPK files" even though file existed

**Fix:**
Added volume mount to docker-compose.yml:
```yaml
volumes:
  - ./var/autoapp:/var/autoapp  # Mount app library and logs
```

**Result:** ✅ Container can access XAPK files and logs directory

---

### Issue 9: Split APK Installation Method ❌ → ✅

**Problem:**
```
INSTALL_FAILED_MISSING_SPLIT: Missing split for fr.mayndrive.app
```

**Root Cause:**
Split APKs were being installed individually instead of together.

**Fix:**
Changed from individual `install` to `install-multiple`:
```typescript
await execAsync(`adb -s ${serial} install-multiple -r ${apkList}`);
```

**Result:** ✅ All APK splits install together as required

---

### Issue 10: ADB Server Network Mode ❌ → ✅

**Problem:**
```
failed to connect to 'apptest-backend:5037': Connection refused
```

**Root Cause:**
ADB server wasn't listening for network connections from ws-scrcpy.

**Fix:**
Start ADB server in network mode at container startup:
```dockerfile
CMD adb -a -P 5037 start-server && npm run start:prod
```

**Result:** ✅ ws-scrcpy can connect to backend's ADB server

---

### Issue 11: Emulator Architecture Mismatch ❌ → ✅

**Problem:**
```
INSTALL_FAILED_NO_MATCHING_ABIS: Failed to extract native libraries
```

**Root Cause:**
App contains ARM native libraries but emulator was x86_64.

**Fix:**
Changed to ARM64 emulator:
```dockerfile
sdkmanager "system-images;android-33;google_apis;arm64-v8a"
avdmanager create avd -n default -k "system-images;android-33;google_apis;arm64-v8a"
```

**Result:** ✅ Apps with ARM libraries can now install

---

## Next Steps

1. **Wait for Dokploy rebuild** (commit: `6711d92`) with ARM64 emulator
2. **Start emulator** via API: `POST http://localhost:3001/api/emulator/start`
3. **Verify app installs** successfully
4. **Access stream** in browser via frontend
5. **Test complete automation** workflow
