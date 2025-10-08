# Troubleshooting — Emulator Control Stack

## Log Locations
- Backend orchestrator: `var/log/autoapp/backend.log`
- ws-scrcpy streamer: run with `--log-level debug` to stdout (captured in terminal)
- Emulator: `${ANDROID_SDK_ROOT}/emulator/logs/` and `~/.android/avd/autoapp-local.avd/*.log`

## Common Issues

### Boot timeout
**Symptoms**: UI shows error "Boot completion timed out" after Start Emulator.

**Checks**
1. Ensure hardware acceleration is available (`emulator -accel-check`).
2. Confirm AVD exists and boots via `emulator @autoapp-local` manually.
3. Inspect backend log for `BOOT_FAILED`; verify `sys.boot_completed` property flips to `1`.
4. Delete corrupted AVD: `avdmanager delete avd -n autoapp-local` then rerun `scripts/setup-avd.sh`.

### Stream unavailable; retrying…
**Symptoms**: Banner shows "Stream unavailable; retrying…" while emulator reports Running.

**Checks**
1. Run the standalone ws-scrcpy bridge locally:
   ```bash
   # once per machine
   git clone https://github.com/NetrisTV/ws-scrcpy
   cd ws-scrcpy
   npm install

   # start the bridge (listens on http://127.0.0.1:8000)
   npm start
   ```
2. In the ws-scrcpy UI (gear icon → Interfaces) pick **proxy over adb** when targeting Android emulators.
3. Ensure the stream endpoint responds: `curl -I http://127.0.0.1:8000/?action=stream&udid=emulator-5555` should return `200`.
4. Reload the AutoApp UI; the iframe should display the ws-scrcpy player once the bridge reports "Connected".

### Health endpoint unreachable
**Symptoms**: UI switches to Error with hint to check backend service.

**Checks**
1. Backend dev server running? `npm run dev` inside `backend/`.
2. Confirm port binding: `ss -ltn sport = :8080` should show `127.0.0.1`.
3. Inspect `var/log/autoapp/backend.log` for crash stack traces.
4. Run `curl http://127.0.0.1:8080/api/health` in terminal; errors indicate backend failure.

### Force stop required
**Symptoms**: Stop attempt fails; banner exposes Force Stop action.

**Checks**
1. Confirm console auth token exists at `~/.emulator_console_auth_token`.
2. If Force Stop still fails, run `adb -s emulator-5555 emu kill` manually.
3. Kill emulator process group: `pkill -f "qemu-system"` as last resort.
4. After cleanup, rerun `scripts/run-local.sh` to restore stack.

### Missing Android CLI tools
**Symptoms**: Backend log shows `Required command 'adb' not found`.

**Resolution**: Install Android SDK tools, export `ANDROID_SDK_ROOT`, and add `$ANDROID_SDK_ROOT/platform-tools` to PATH before restarting backend.

## Maintenance Tips
- Rotate backend logs periodically to keep under 30-day retention (`logrotate` or manual truncation).
- Keep Node.js and npm updated to match project requirements (Node 20 LTS recommended).
- Regenerate emulator images after Android SDK updates to avoid stale system components.
