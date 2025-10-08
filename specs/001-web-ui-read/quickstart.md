# Quickstart — Web UI: Read-Only Android Stream + Start/Stop Emulator (v1)

## Prerequisites
- Ubuntu 25.04 host with ≥6 vCPU, ≥12 GB RAM
- Android SDK command-line tools installed (sdkmanager, avdmanager, emulator, adb available in `PATH`)
- Node.js 20 LTS and npm (or pnpm) installed locally
- Chromium- or Firefox-based browser with Media Source Extensions (MSE) enabled

## One-Time Setup
1. **Install Android system image & create AVD**
   ```bash
   # From repository root
   ./scripts/setup-avd.sh
   ```
   - Installs `system-images;android-34;google_apis;x86_64`
   - Creates rooted AVD named `autoapp-local`
2. **Install JavaScript dependencies**
   ```bash
   cd backend && npm install
   cd ../frontend && npm install
   ```
3. **Bootstrap ws-scrcpy**
   ```bash
   npm install --global ws-scrcpy
   ```
   (Alternatively add `ws-scrcpy` as a backend dependency and expose via npm scripts.)

## Running the Stack (Development)
1. Run the helper script to launch backend, streamer, and frontend together:
   ```bash
   ./scripts/run-local.sh
   ```
   - Backend API → http://127.0.0.1:8080
   - ws-scrcpy streamer → ws://127.0.0.1:8081
   - Frontend SPA → http://127.0.0.1:5173
2. Open the control UI at `http://127.0.0.1:5173`.
3. Prefer manual control? Start each service in separate terminals:
   ```bash
   # Backend API
   cd backend && npm run dev

   # Streamer (requires ws-scrcpy installed globally)
   ws-scrcpy --address 127.0.0.1 --port 8081 --serial emulator-5555 --disable-control

   # Frontend
   cd frontend && npm run dev -- --host 127.0.0.1 --port 5173
   ```

## Operational Flow
1. Click **Start Emulator** → backend enters Booting, launches emulator headless, waits for `sys.boot_completed`.
2. When Running, the UI auto-requests `/stream/url`, receives a one-time ws-scrcpy URL, and renders the stream read-only.
3. Click **Stop Emulator** to trigger console kill ladder; backend stops ws-scrcpy and returns to Stopped.
4. On errors, the UI presents a banner with a link to backend/emulator logs (see `var/log/autoapp/*.log`).

## Testing
- Backend integration tests: `cd backend && npm test`
- UI component tests: `cd frontend && npm test`
- End-to-end smoke (mocked backend): `cd frontend && npm run test:e2e`

## Cleanup
- Stop dev servers (Ctrl+C)
- Remove AVD if needed: `avdmanager delete avd -n autoapp-local`
- Logs retained for 30 days under `var/log/autoapp/`
