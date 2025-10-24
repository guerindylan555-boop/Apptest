# AutoApp Streaming Stack – Operator Notes

This folder contains the host-side helpers that keep the Android emulator and
`ws-scrcpy` streamer aligned with the Docker backend running under Dokploy.

## Quick Start
- Ensure Dokploy has pulled the latest commit (`main`) and both Docker services
  (`apptest-backend`, `apptest-frontend`) are healthy.
- From the repository root run:
  ```bash
  scripts/working/start_stream_stack.sh
  ```
  The script:
  - Restarts the host adb daemon on `127.0.0.1:5038`
  - Boots the `autoapp-local` AVD headlessly
  - Launches `ws-scrcpy` on port `8000`
  - Streams logs to `var/log/autoapp/emulator.log` and `var/log/autoapp/ws-scrcpy.log`

## Verifying the Stream
1. Check backend health:
   ```bash
   curl -s http://localhost:3001/api/health
   ```
   State should be `Running`.
2. Mint a stream ticket (adjust the `Host` header for remote access):
   ```bash
   curl -s http://localhost:3001/api/stream/url
   curl -s -H 'Host: 82.165.175.97' http://localhost:3001/api/stream/url
   ```
3. Open the returned URL (e.g., `http://82.165.175.97:8000/#!...`) in the browser;
   you should see the live emulator feed.

## Shutdown / Reset
- Stop the stack with standard tools:
  ```bash
  pkill -f 'qemu-system.*@autoapp-local'
  pkill -f 'ws-scrcpy/dist/index.js'
  adb -P 5038 kill-server    # optional if you need a clean slate
  ```
- Rerun `start_stream_stack.sh` whenever you need a fresh emulator + streamer.

## Troubleshooting
- If the script exits early, inspect the log it references and fix missing
  binaries (`ANDROID_SDK_ROOT`, ws-scrcpy build).
- When the backend reports `Stopped`, ensure the Docker stack has redeployed the
  rollback commit (`Remove lifecycle controls...`) and rerun the script.
- A blank player usually means `ws-scrcpy` is down—tail
  `var/log/autoapp/ws-scrcpy.log` while reloading the stream page.
