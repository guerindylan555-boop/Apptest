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

# Start adb server in the background (ignore failures if already running)
"$ADB_BIN" kill-server >/dev/null 2>&1 || true
"$ADB_BIN" start-server >/dev/null 2>&1 || true

exec npm run start:prod
