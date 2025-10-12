# Troubleshooting — Emulator Control Stack

## Log Locations
- Backend orchestrator: `var/log/autoapp/backend.log`
- Backend dev server (when launched via script): `var/log/autoapp/backend-dev.log`
- ws-scrcpy streamer: `var/log/autoapp/ws-scrcpy.log`
- Frontend dev server: `var/log/autoapp/frontend-dev.log`
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
1. Re-run `./scripts/run-everything.sh` to recycle all streamer/backend/frontend processes and free port 8000.
2. Inspect `var/log/autoapp/ws-scrcpy.log` for `EADDRINUSE` or decoder errors; resolve port conflicts (kill stray `node ./index.js` processes) before retrying.
3. Confirm the backend is issuing WebCodecs tickets: `curl http://<server-host>:3001/api/stream/url` should return a URL containing `player=webcodecs` when the emulator is Running.
4. Open `http://<server-host>:8000/` only for diagnostics; the embedded iframe should attach automatically without manually selecting a player.

### Health endpoint unreachable
**Symptoms**: UI switches to Error with hint to check backend service.

**Checks**
1. Backend dev server running? `npm run dev` inside `backend/`.
2. Confirm port binding: `ss -ltn sport = :3001` should show `0.0.0.0` (or your configured host).
3. Inspect `var/log/autoapp/backend.log` for crash stack traces.
4. Run `curl http://<server-host>:3001/api/health` in terminal; errors indicate backend failure.

### Force stop required
**Symptoms**: Stop attempt fails; banner exposes Force Stop action.

**Checks**
1. Confirm console auth token exists at `~/.emulator_console_auth_token`.
2. If Force Stop still fails, run `adb -s emulator-5555 emu kill` manually.
3. Kill emulator process group: `pkill -f "qemu-system"` as last resort.
4. After cleanup, rerun `scripts/run-everything.sh` to restore the stack.

### Missing Android CLI tools
**Symptoms**: Backend log shows `Required command 'adb' not found`.

**Resolution**: Install Android SDK tools, export `ANDROID_SDK_ROOT`, and add `$ANDROID_SDK_ROOT/platform-tools` to PATH before restarting backend.

## Maintenance Tips
- Rotate backend logs periodically to keep under 30-day retention (`logrotate` or manual truncation).
- Keep Node.js and npm updated to match project requirements (Node 20 LTS recommended).
- Regenerate emulator images after Android SDK updates to avoid stale system components.
