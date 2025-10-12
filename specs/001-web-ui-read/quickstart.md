# Quickstart — AutoApp Emulator Control UI

## Overview
Local-only web UI for Android emulator control with read-only WebSocket streaming. Features start/stop lifecycle, an embedded ws-scrcpy player, and comprehensive error handling.

## Prerequisites
- Node.js 20 LTS or later
- Android SDK tools with emulator and ADB
- AVD (Android Virtual Device) configured
- `adb` and `emulator` commands in PATH
- Local copy of the patched `ws-scrcpy` bridge (bundled in this repository)

## Setup

1. **Install dependencies**
   ```bash
   cd backend && npm install
   cd ../frontend && npm install
   ```

2. **Environment Configuration**
   - Ensure `ANDROID_HOME` and `ANDROID_SDK_ROOT` are set
   - Verify AVD exists: `emulator -list-avds`
   - Configure environment variables (see `backend/.env.example`)
   - Optional: override stream defaults via `WS_SCRCPY_HOST`, `WS_SCRCPY_PORT`, `WS_SCRCPY_PLAYER`, `WS_SCRCPY_REMOTE`
   - The repository includes a patched `ws-scrcpy/` workspace; `scripts/run-everything.sh` will install dependencies on first run.

## Development

1. **Launch the full stack**
   ```bash
   ./scripts/run-everything.sh
   ```
   - Orchestrates ws-scrcpy (port 8000), backend (port 3001), and frontend (port 5173)
   - Writes logs to `var/log/autoapp/`
   - Automatically reapplies the embedded-player patch and cleans stale processes before restart

2. **Manual starts (optional)**
   - **Backend**
     ```bash
     cd backend
     npm run dev
     ```
   - **Frontend**
     ```bash
     cd frontend
     npm run dev
     ```
   - **ws-scrcpy**
     ```bash
     cd ws-scrcpy/dist
     node ./index.js
     ```
   Use the manual approach only if you need individual component debugging; otherwise prefer the launcher script.

## Usage Workflow

1. **Start Emulator**
   - Click "Start Emulator" button
   - Monitor state badge: Stopped → Booting → Running
   - Boot typically takes 30-60 seconds

2. **Stream Validation**
   - When state shows "Running", the embedded ws-scrcpy player should appear
   - Stream tickets default to the WebCodecs player with autoplay enabled
   - The ws-scrcpy dashboard at `http://127.0.0.1:8000/` remains available for diagnostics

3. **Stop Emulator**
   - Click "Stop Emulator" for graceful shutdown
   - State transitions: Running → Stopping → Stopped
   - Stream automatically disconnects and clears canvas

4. **Error Recovery**
   - **Normal failures**: Use "Retry" button for boot/stream issues
   - **Stuck processes**: Use "Force Stop" when normal stop fails
   - **Backend issues**: Check logs at `var/log/autoapp/backend.log`

## Stream Embedding
- UI renders the ws-scrcpy player inside an iframe
- Backend issues short-lived tickets that select WebCodecs by default; alternative players remain available through the ws-scrcpy UI if required
- Placeholder shown while emulator boots or stops

## Force Stop Guidance
- Only use when normal stop sequence fails
- Terminates emulator process forcefully
- May leave orphaned processes requiring manual cleanup
- Check system processes: `ps aux | grep emulator`

## Testing

**Backend Tests**
```bash
cd backend
npm test
```

**Frontend Tests**
```bash
cd frontend
npm test
```

**Linting**
```bash
# Both directories
npm run lint
```

## Troubleshooting

1. **Boot timeout**: Increase `EMULATOR_BOOT_TIMEOUT_MS` in backend/.env
2. **Port conflicts**: Check `EMULATOR_CONSOLE_PORT` and `EMULATOR_ADB_PORT`
3. **ADB issues**: Verify device connectivity: `adb devices`
4. **Stream problems**: Confirm `scripts/run-everything.sh` completed without `EADDRINUSE`; if necessary, rerun the script to recycle lingering streamer processes
5. **Permission issues**: Check backend log file permissions

## Log Locations
- **Backend**: `var/log/autoapp/backend.log`
- **Frontend**: Browser developer console
- **Streamer**: Integrated with backend logger
