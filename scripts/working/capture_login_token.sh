#!/bin/bash
# MaynDrive Login Token Capture - PROVEN WORKING METHOD
# Based on CAPTURE_SUCCESS_REPORT.md validated approach

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

SERIAL="${EMULATOR_SERIAL:-emulator-5554}"
ADB_PORT="${ANDROID_ADB_SERVER_PORT:-${ADB_PORT:-}}"
ADB_BIN="${ADB_BIN:-adb}"
FRIDA_BIN="${FRIDA_BIN:-frida}"
LOGIN_SCRIPT="${LOGIN_SCRIPT:-$SCRIPT_DIR/mayndrive_login_flow.js}"
FRIDA_SCRIPT="${FRIDA_SCRIPT:-$ROOT_DIR/mayndrive_simple_capture.js}"
PACKAGE_NAME="fr.mayndrive.app"
LOG_FILE="${MAYNDRIVE_CAPTURE_LOG:-$(mktemp /tmp/mayndrive_token_capture.XXXX.log)}"

ADB_ARGS=()
if [[ -n "$ADB_PORT" ]]; then
  ADB_ARGS+=("-P" "$ADB_PORT")
fi
ADB_ARGS+=("-s" "$SERIAL")

adb_cmd() {
  "$ADB_BIN" "${ADB_ARGS[@]}" "$@"
}

echo "════════════════════════════════════════════════════"
echo " MaynDrive Login Token Capture (PROVEN METHOD)"
echo "════════════════════════════════════════════════════"
echo " Device: $SERIAL"
if [[ -n "$ADB_PORT" ]]; then
  echo " ADB Port: $ADB_PORT"
fi
echo " Capture Script: mayndrive_simple_capture.js"
echo " Log: $LOG_FILE"
echo "════════════════════════════════════════════════════"

if [[ ! -f "$LOGIN_SCRIPT" ]]; then
  echo "ERROR: Login script not found at $LOGIN_SCRIPT" >&2
  exit 1
fi

if [[ ! -f "$FRIDA_SCRIPT" ]]; then
  echo "ERROR: Frida capture script not found at $FRIDA_SCRIPT" >&2
  exit 1
fi

echo "[1/6] Starting login automation (background)..."
(
  ANDROID_ADB_SERVER_PORT="${ADB_PORT:-}" \
    ADB_BIN="$ADB_BIN" \
    EMULATOR_SERIAL="$SERIAL" \
    node "$LOGIN_SCRIPT"
) > /tmp/login_automation.log 2>&1 &
LOGIN_PID=$!

echo "    Login PID: $LOGIN_PID"
echo "[2/6] Waiting for app to launch..."
sleep 8

echo "[3/6] Finding app process..."
PID=""
for attempt in {1..40}; do
  if PID_RAW="$(adb_cmd shell pidof "$PACKAGE_NAME" 2>/dev/null)"; then
    PID="$(echo "$PID_RAW" | tr -d '\r\n' | awk '{print $NF}')"
    if [[ -n "$PID" && "$PID" =~ ^[0-9]+$ ]]; then
      break
    fi
  fi
  PID=""
  sleep 1
done

if [[ -z "$PID" ]]; then
  echo "ERROR: Unable to find running process for $PACKAGE_NAME" >&2
  echo "  Processes found:"
  adb_cmd shell ps | grep -i mayn || true
  wait "$LOGIN_PID" 2>/dev/null || true
  exit 1
fi

echo "    App PID: $PID"
echo "[4/6] Attaching Frida (ATTACH mode to bypass detection)..."

$FRIDA_BIN -D "$SERIAL" -p "$PID" -l "$FRIDA_SCRIPT" \
  > "$LOG_FILE" 2>&1 &
FRIDA_PID=$!
echo "    Frida PID: $FRIDA_PID"
sleep 5

if ! ps -p "$FRIDA_PID" > /dev/null 2>&1; then
  echo "ERROR: Frida failed to attach!" >&2
  cat "$LOG_FILE"
  wait "$LOGIN_PID" 2>/dev/null || true
  exit 1
fi

echo "    SUCCESS: Frida attached and hooks installed"
echo "[5/6] Waiting for login automation..."

wait "$LOGIN_PID" 2>/dev/null || {
  echo "    Login automation finished/exited"
}

sleep 5

if ps -p "$FRIDA_PID" > /dev/null 2>&1; then
  kill "$FRIDA_PID" >/dev/null 2>&1 || true
  wait "$FRIDA_PID" 2>/dev/null || true
fi

echo "[6/6] Extracting token from log..."

TOKEN_LINES="$(grep -i "Bearer eyJ" "$LOG_FILE" || true)"

if [[ -z "$TOKEN_LINES" ]]; then
  echo "WARNING: No Bearer token found"
  echo ""
  echo "Last 50 lines of Frida log:"
  tail -50 "$LOG_FILE"
  echo ""
  echo "Full logs:"
  echo "  Frida: $LOG_FILE"
  echo "  Login: /tmp/login_automation.log"
  exit 1
fi

TOKEN="$(echo "$TOKEN_LINES" | tail -n 1 | grep -oE 'Bearer eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' || true)"

if [[ -z "$TOKEN" ]]; then
  echo "WARNING: Token found but parsing failed"
  echo "Raw: $TOKEN_LINES"
  exit 1
fi

echo ""
echo "════════════════════════════════════════════════════"
echo " SUCCESS - Auth Token Captured!"
echo "════════════════════════════════════════════════════"
echo ""
echo "$TOKEN"
echo ""
echo "════════════════════════════════════════════════════"
echo "Logs saved:"
echo "  Capture: $LOG_FILE"
echo "  Login: /tmp/login_automation.log"
echo ""
