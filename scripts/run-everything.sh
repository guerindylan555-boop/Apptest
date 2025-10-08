#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
WS_SCRCPY_DIR="${WS_SCRCPY_DIR:-$ROOT_DIR/ws-scrcpy}"
LOG_DIR="$ROOT_DIR/var/log/autoapp"
BACKEND_LOG="$LOG_DIR/backend-dev.log"
FRONTEND_LOG="$LOG_DIR/frontend-dev.log"
WS_SCRCPY_LOG="$LOG_DIR/ws-scrcpy.log"

mkdir -p "$LOG_DIR"

kill_if_running() {
  local pattern=$1
  pgrep -f "$pattern" >/dev/null 2>&1 || return 0
  echo "[run-everything] Stopping processes matching '$pattern'"
  pkill -f "$pattern" || true
  sleep 1
  if pgrep -f "$pattern" >/dev/null 2>&1; then
    echo "[run-everything] Force killing remaining '$pattern'"
    pkill -9 -f "$pattern" || true
  fi
}

stop_all() {
  kill_if_running "ws-scrcpy"
  kill_if_running "ts-node-dev --respawn --transpile-only src/index.ts"
  kill_if_running "vite --host"
}

start_ws_scrcpy() {
  if [ ! -d "$WS_SCRCPY_DIR" ]; then
    echo "[run-everything] Cloning ws-scrcpy into $WS_SCRCPY_DIR"
    git clone https://github.com/NetrisTV/ws-scrcpy "$WS_SCRCPY_DIR"
  fi

  pushd "$WS_SCRCPY_DIR" >/dev/null
  if [ ! -d node_modules ]; then
    echo "[run-everything] Installing ws-scrcpy dependencies"
    npm install
  fi

  if ! grep -q 'embedded-view' src/style/app.css 2>/dev/null; then
    if git apply "$ROOT_DIR/scripts/ws-scrcpy-embedded.patch"; then
      echo "[run-everything] Applied embedded-mode patch to ws-scrcpy"
    else
      echo "[run-everything] Warning: failed to apply embedded patch (maybe already applied)" >&2
    fi
  fi

  echo "[run-everything] Starting ws-scrcpy"
  nohup npm start > "$WS_SCRCPY_LOG" 2>&1 &
  WS_PID=$!
  popd >/dev/null
}

start_backend() {
  pushd "$BACKEND_DIR" >/dev/null
  echo "[run-everything] Starting backend"
  nohup npm run dev > "$BACKEND_LOG" 2>&1 &
  BACKEND_PID=$!
  popd >/dev/null
}

start_frontend() {
  pushd "$FRONTEND_DIR" >/dev/null
  echo "[run-everything] Starting frontend"
  nohup npm run dev > "$FRONTEND_LOG" 2>&1 &
  FRONTEND_PID=$!
  popd >/dev/null
}

main() {
  stop_all
  start_ws_scrcpy
  start_backend
  start_frontend

  echo "[run-everything] Services launched"
  echo "  ws-scrcpy log: $WS_SCRCPY_LOG"
  echo "  backend log: $BACKEND_LOG"
  echo "  frontend log: $FRONTEND_LOG"
  echo "[run-everything] Embedded stream is auto-configured; the ws-scrcpy dashboard remains available at http://127.0.0.1:8000/ if you need to inspect it."
}

main "$@"
