# Quickstart — AutoApp Emulator Control UI

## Overview
Local-only web UI for Android emulator control with read-only WebSocket streaming. Features start/stop lifecycle, an embedded ws-scrcpy player, and comprehensive error handling.

## Prerequisites
- Node.js 20 LTS or later
- Android SDK tools with emulator and ADB
- AVD (Android Virtual Device) configured
- `adb` and `emulator` commands in PATH
- ws-scrcpy bridge installed and accessible

## Setup

1. **Install dependencies**
   ```bash
   cd backend && npm install
   cd ../frontend && npm install
   ```

2. **Environment Configuration**
   - Ensure `ANDROID_HOME` and `ANDROID_SDK_ROOT` are set
   - Verify AVD exists: `emulator -list-avds`
   - Configure environment variables (see backend/.env.example)
   - Clone and bootstrap ws-scrcpy (once per machine):
     ```bash
     git clone https://github.com/NetrisTV/ws-scrcpy
     cd ws-scrcpy && npm install
     ```

## Development

1. **Start ws-scrcpy streamer**
   ```bash
   cd path/to/ws-scrcpy
   npm start
   ```
   - Open `http://127.0.0.1:8000/` → gear icon → select **proxy over adb**

2. **Start Backend**
   ```bash
   cd backend
   npm run dev
   ```
   - API available at `http://127.0.0.1:7070`
   - Health endpoint: `GET /api/health`
   - Logs written to `var/log/autoapp/backend.log`

3. **Start Frontend**
   ```bash
   cd frontend
   npm run dev
   ```
   - UI available at `http://127.0.0.1:8080`
   - Hot reload enabled for development

## Usage Workflow

1. **Start Emulator**
   - Click "Start Emulator" button
   - Monitor state badge: Stopped → Booting → Running
   - Boot typically takes 30-60 seconds

2. **Stream Validation**
   - When state shows "Running", the embedded ws-scrcpy player should appear
   - The iframe points to `http://127.0.0.1:8000/?action=stream&udid=<serial>&player=mse`
   - Switch players in the ws-scrcpy UI if MSE fails (e.g., TinyH264)

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
- Player selection (MSE/WebCodecs/TinyH264) managed via ws-scrcpy controls
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
4. **Stream problems**: Ensure ws-scrcpy bridge is running
5. **Permission issues**: Check backend log file permissions

## Log Locations
- **Backend**: `var/log/autoapp/backend.log`
- **Frontend**: Browser developer console
- **Streamer**: Integrated with backend logger
