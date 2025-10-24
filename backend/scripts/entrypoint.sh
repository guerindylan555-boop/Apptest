#!/usr/bin/env bash
set -euo pipefail

ADB_BIN="${ADB_BIN:-/opt/android-sdk/platform-tools/adb}"
ANDROID_HOME="${ANDROID_HOME:-/root/.android}"

# DO NOT set ADB_SERVER_SOCKET - let ADB use default local socket
export ADB_SERVER_PORT=5037
export ANDROID_ADB_SERVER_PORT=5037

# Ensure IPv6 loopback entry exists for emulator services
if ! grep -qE '^::1\s' /etc/hosts; then
  echo '::1 localhost ip6-localhost ip6-loopback' >> /etc/hosts
fi

echo "[entrypoint] Preparing ADB environment..."

# Create .android directory with proper permissions
mkdir -p "$ANDROID_HOME"
chmod 700 "$ANDROID_HOME"

# Generate ADB keys if they don't exist
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

# Start ADB server - it will automatically fork to background
if "$ADB_BIN" start-server 2>&1; then
  echo "[entrypoint] ADB server start command completed"
else
  echo "[entrypoint] WARNING: ADB server start command failed"
fi

# Verify it's running
sleep 2
if "$ADB_BIN" devices >/dev/null 2>&1; then
  ADB_PID=$(pgrep -f "adb.*fork-server" || echo "unknown")
  echo "[entrypoint] ADB server verified and running (PID: $ADB_PID)"
else
  echo "[entrypoint] WARNING: ADB server not responding, will retry on first emulator start"
fi

exec npm run start:prod
