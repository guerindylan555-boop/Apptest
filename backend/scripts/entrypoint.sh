#!/usr/bin/env bash
set -euo pipefail

ADB_BIN="${ADB_BIN:-/opt/android-sdk/platform-tools/adb}"
ANDROID_HOME="${ANDROID_HOME:-/root/.android}"

export ADB_SERVER_PORT=5037
export ANDROID_ADB_SERVER_PORT=5037
export ADB_SERVER_SOCKET=tcp:127.0.0.1:5037

# Ensure IPv6 loopback entry exists for emulator services
if ! grep -qE '^::1\s' /etc/hosts; then
  echo '::1 localhost ip6-localhost ip6-loopback' >> /etc/hosts
fi

echo "[entrypoint] Preparing ADB environment..."

# Create .android directory with proper permissions
mkdir -p "$ANDROID_HOME"
chmod 700 "$ANDROID_HOME"

# Generate ADB keys if they don't exist (required for ADB server to start)
if [ ! -f "$ANDROID_HOME/adbkey" ]; then
  echo "[entrypoint] Generating ADB keys..."
  "$ADB_BIN" keygen "$ANDROID_HOME/adbkey"
fi

# Ensure keys have proper permissions
if [ -f "$ANDROID_HOME/adbkey" ]; then
  chmod 600 "$ANDROID_HOME/adbkey"
  chmod 644 "$ANDROID_HOME/adbkey.pub" 2>/dev/null || true
fi

echo "[entrypoint] Starting ADB server..."
# Kill any existing server
"$ADB_BIN" kill-server 2>&1 || true
sleep 1

# Start ADB server in background
"$ADB_BIN" -L tcp:5037 fork-server server --reply-fd 3 3>&1 >/dev/null 2>&1 &
ADB_PID=$!

# Wait for ADB server to be ready
for i in {1..10}; do
  if "$ADB_BIN" devices >/dev/null 2>&1; then
    echo "[entrypoint] ADB server started successfully (PID: $ADB_PID)"
    break
  fi
  if [ $i -eq 10 ]; then
    echo "[entrypoint] WARNING: ADB server not responding after 10 attempts"
  fi
  sleep 1
done

exec npm run start:prod
