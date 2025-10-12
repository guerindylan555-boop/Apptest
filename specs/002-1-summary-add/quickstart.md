# Quickstart – Apps Library & Instrumentation Hub

## Prerequisites
- Local Ubuntu host with Android SDK platform tools (`adb`, `aapt2`), rooted emulator image (API 34) running.
- Frida binaries (`frida-server` for emulator ABI, `frida-tools`) available on PATH (pending constitution exception).
- mitmproxy installed locally if proxy capture is required.
- Backend and frontend dependencies installed (`npm install` within `/backend` and `/frontend`).

## Launch Stack
```bash
# Terminal 1 – backend
cd backend
PORT=3001 HOST=127.0.0.1 npm run dev

# Terminal 2 – frontend
cd frontend
VITE_BACKEND_URL=http://127.0.0.1:3001/api npm run dev
```
Open `http://127.0.0.1:5173` in the browser and switch to the **Apps** section.

## Upload & Catalogue APK
1. Drag and drop a `.apk` file into the upload target or use the file picker.
2. Wait for the “Analyzing APK…” status to complete; metadata should populate in the list.
3. Optionally rename the entry or pin it to exempt from retention sweeps.

## Install & Launch
1. Select an APK row, review metadata in the detail panel.
2. Toggle “Allow downgrade” or “Auto-grant runtime permissions” if needed.
3. Click **Install & Launch** and monitor status chips for install outcome and launch resolution.

## Frida Instrumentation (pending governance approval)
1. Toggle **Frida Server** to “On”; confirm status changes to active.
2. Select the running package from the dropdown and provide a local script path.
3. Click **Attach & Load Script**; watch the mini-console for confirmation or errors.

## Logcat & Proxy Tools

### Logcat Capture
1. In the **Logcat Capture** panel, optionally specify package filters (e.g., `com.example.app`) or tag filters (e.g., `ActivityManager`).
2. Click **Start Capture** to begin logging; the session appears in the list with a green "ACTIVE" badge.
3. Use **Pause** to temporarily stop capture, **Resume** to continue, or **Stop** to finalize.
4. Once stopped, click **View** to preview logs inline or **Download** to save the `.txt` file locally.
5. Active captures show real-time file size; filter text is displayed for quick reference.

### HTTP Proxy
1. In the **HTTP Proxy** panel, configure the host (default: `127.0.0.1`) and port (default: `8080`).
2. Click **Enable Proxy** to route emulator traffic through the specified proxy.
3. To intercept HTTPS traffic:
   - Start your proxy tool (e.g., `mitmproxy`, `mitmweb`, Burp Suite).
   - Navigate to `mitm.it` on the emulator's Chrome browser.
   - Download and install the Android certificate via **Settings → Security → Install from storage**.
4. Click **Disable Proxy** when finished; the emulator returns to direct network access.
5. Refer to the on-screen guidance for CA certificate installation and network security configuration tips.

## Retention & Cleanup
- Unpinned APKs and associated artifacts older than 30 days are purged automatically by the nightly sweep.
- Use the Apps list to delete entries manually or unpin when cleanup is desired.
