#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
STREAM_HOST=${STREAM_HOST:-127.0.0.1}
STREAM_PORT=${STREAM_PORT:-8081}
EMULATOR_SERIAL=${EMULATOR_SERIAL:-emulator-5555}

cleanup() {
  echo "[run-local] Shutting down child processes"
  pkill -P $$ >/dev/null 2>&1 || true
}

trap cleanup EXIT

if ! command -v ws-scrcpy >/dev/null 2>&1; then
  echo "[run-local] ws-scrcpy not found in PATH. Install it via 'npm install -g ws-scrcpy'." >&2
fi

pushd "$BACKEND_DIR" >/dev/null
npm run dev &
BACKEND_PID=$!
popd >/dev/null

echo "[run-local] Backend PID $BACKEND_PID"

if command -v ws-scrcpy >/dev/null 2>&1; then
  echo "[run-local] Starting ws-scrcpy on ws://$STREAM_HOST:$STREAM_PORT"
  ws-scrcpy --address "$STREAM_HOST" --port "$STREAM_PORT" --serial "$EMULATOR_SERIAL" --disable-control &
  STREAM_PID=$!
else
  STREAM_PID=
fi

pushd "$FRONTEND_DIR" >/dev/null
npm run dev &
FRONTEND_PID=$!
popd >/dev/null

echo "[run-local] Frontend PID $FRONTEND_PID"

wait
