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

# Start adb server with retry logic
echo "[entrypoint] Starting ADB server..."
"$ADB_BIN" kill-server 2>&1 || true

MAX_RETRIES=5
for i in $(seq 1 $MAX_RETRIES); do
  if "$ADB_BIN" start-server 2>&1; then
    echo "[entrypoint] ADB server started successfully"
    break
  fi
  echo "[entrypoint] ADB server start attempt $i failed, retrying..."
  sleep 1
done

# Verify ADB server is responding
if "$ADB_BIN" devices > /dev/null 2>&1; then
  echo "[entrypoint] ADB server verified and responding"
else
  echo "[entrypoint] WARNING: ADB server may not be fully ready"
fi

exec npm run start:prod
