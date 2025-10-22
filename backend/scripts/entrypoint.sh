#!/usr/bin/env bash
set -euo pipefail

ADB_BIN="${ADB_BIN:-adb}"
ADB_PORT="${ADB_SERVER_PORT:-${ANDROID_ADB_SERVER_PORT:-5037}}"
ADB_SOCKET="${ADB_SERVER_SOCKET:-tcp:127.0.0.1:${ADB_PORT}}"

export ADB_SERVER_PORT="${ADB_PORT}"
export ANDROID_ADB_SERVER_PORT="${ADB_PORT}"
export ADB_SERVER_SOCKET="${ADB_SOCKET}"

# Ensure IPv6 loopback entry exists for emulator services
if ! grep -qE '^::1\s' /etc/hosts; then
  echo '::1 localhost ip6-localhost ip6-loopback' >> /etc/hosts
fi

# Start adb server in the background (ignore failures if already running)
if command -v "$ADB_BIN" >/dev/null 2>&1; then
  "$ADB_BIN" start-server >/dev/null 2>&1 || true
fi

exec npm run start:prod
