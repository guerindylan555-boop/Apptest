#!/usr/bin/env bash
set -euo pipefail

ADB_BIN="${ADB_BIN:-/opt/android-sdk/platform-tools/adb}"

export ADB_SERVER_PORT=5037
export ANDROID_ADB_SERVER_PORT=5037
export ADB_SERVER_SOCKET=tcp:127.0.0.1:5037

# Ensure IPv6 loopback entry exists for emulator services
if ! grep -qE '^::1\s' /etc/hosts; then
  echo '::1 localhost ip6-localhost ip6-loopback' >> /etc/hosts
fi

echo "[entrypoint] Starting ADB server as background daemon..."
# Kill any stale server
"$ADB_BIN" kill-server 2>&1 || true
sleep 1

# Start ADB server in background using fork mode
"$ADB_BIN" -L tcp:5037 fork-server server --reply-fd 3 3>&1 >/dev/null 2>&1 &
ADB_PID=$!

# Give it a moment to bind to the port
sleep 2

# Verify it's running
if kill -0 $ADB_PID 2>/dev/null; then
  echo "[entrypoint] ADB server started successfully (PID: $ADB_PID)"
else
  echo "[entrypoint] WARNING: ADB server process died immediately"
fi

exec npm run start:prod
