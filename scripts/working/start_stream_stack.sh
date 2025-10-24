#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# AutoApp host bootstrap: starts adb @5038, autoapp-local emulator, ws-scrcpy #
###############################################################################

log() {
  printf '[start-stream] %s\n' "$*"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-/home/blhack/android-sdk}"
ANDROID_HOME="${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
ADB_BIN="${ADB_BIN:-$ANDROID_SDK_ROOT/platform-tools/adb}"
EMULATOR_BIN="${EMULATOR_BIN:-$ANDROID_SDK_ROOT/emulator/emulator}"
WS_SCRCPY_DIR="${WS_SCRCPY_DIR:-$ROOT_DIR/ws-scrcpy}"

ADB_HOST="${ADB_HOST:-127.0.0.1}"
ADB_PORT="${ADB_PORT:-5038}"
AVD_NAME="${AVD_NAME:-autoapp-local}"
EMULATOR_SERIAL="${EMULATOR_SERIAL:-emulator-5554}"
WS_SCRCPY_PORT="${WS_SCRCPY_PORT:-8000}"

LOG_DIR="${LOG_DIR:-$ROOT_DIR/var/log/autoapp}"
mkdir -p "$LOG_DIR"

PATH="$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$PATH"

require_file() {
  local file=$1
  local label=$2
  if [[ ! -x "$file" && ! -f "$file" ]]; then
    printf '[start-stream] ERROR: expected %s at %s\n' "$label" "$file" >&2
    exit 1
  fi
}

require_file "$ADB_BIN" "adb binary"
require_file "$EMULATOR_BIN" "emulator binary"

if [[ ! -d "$WS_SCRCPY_DIR/dist" ]]; then
  printf '[start-stream] ERROR: ws-scrcpy dist bundle not found at %s/dist\n' "$WS_SCRCPY_DIR" >&2
  printf '               Build it first (push from Dokploy or run npm run dist inside ws-scrcpy)\n' >&2
  exit 1
fi

stop_if_running() {
  local pattern=$1
  local name=$2
  if pgrep -f "$pattern" >/dev/null 2>&1; then
    log "Existing $name detected; terminating"
    pkill -f "$pattern" || true
    sleep 1
  fi
}

log "Preparing clean environment"
stop_if_running "qemu-system-x86_64-headless @${AVD_NAME}" "emulator"
stop_if_running "$WS_SCRCPY_DIR/dist/index.js" "ws-scrcpy"

log "Restarting adb server on tcp:$ADB_HOST:$ADB_PORT"
"$ADB_BIN" -P "$ADB_PORT" kill-server >/dev/null 2>&1 || true
"$ADB_BIN" -a -H "$ADB_HOST" -P "$ADB_PORT" start-server >/dev/null

log "Starting emulator @$AVD_NAME"
nohup env \
  ANDROID_SDK_ROOT="$ANDROID_SDK_ROOT" \
  ANDROID_HOME="$ANDROID_HOME" \
  JAVA_HOME="$JAVA_HOME" \
  ANDROID_ADB_SERVER_PORT="$ADB_PORT" \
  QT_QPA_PLATFORM=offscreen \
  QT_LOGGING_RULES='*.debug=false;qt.qpa.*=false' \
  LIBGL_ALWAYS_SOFTWARE=1 \
  "$EMULATOR_BIN" @"$AVD_NAME" \
    -no-window \
    -no-boot-anim \
    -no-snapshot \
    -no-audio \
    -gpu swiftshader_indirect \
    -ports 5554,5555 \
  >> "$LOG_DIR/emulator.log" 2>&1 &
EMULATOR_PID=$!
log "Emulator PID $EMULATOR_PID (logs -> $LOG_DIR/emulator.log)"

log "Waiting for emulator serial $EMULATOR_SERIAL to register (timeout 90s)"
for attempt in {1..45}; do
  if "$ADB_BIN" -P "$ADB_PORT" devices | grep -q "$EMULATOR_SERIAL"; then
    log "Emulator detected"
    break
  fi
  sleep 2
  if [[ $attempt -eq 45 ]]; then
    log "ERROR: emulator failed to appear on adb within timeout"
    exit 1
  fi
done

log "Launching ws-scrcpy on port $WS_SCRCPY_PORT"
nohup env \
  ADB_HOST="$ADB_HOST" \
  ADB_PORT="$ADB_PORT" \
  ANDROID_ADB_SERVER_PORT="$ADB_PORT" \
  WS_SCRCPY_PORT="$WS_SCRCPY_PORT" \
  node "$WS_SCRCPY_DIR/dist/index.js" \
  >> "$LOG_DIR/ws-scrcpy.log" 2>&1 &
WS_PID=$!
log "ws-scrcpy PID $WS_PID (logs -> $LOG_DIR/ws-scrcpy.log)"

log "Bootstrap complete."
log "Verify backend health via: curl -s http://localhost:3001/api/health"
log "Fetch a stream ticket via: curl -s http://localhost:3001/api/stream/url"
