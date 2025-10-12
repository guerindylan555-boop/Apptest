#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
# Export default environment variables for backend/frontend
export EMULATOR_SERIAL=${EMULATOR_SERIAL:-emulator-5555}
export PORT=${PORT:-3001}
export HOST=${HOST:-0.0.0.0}
export LOG_LEVEL=${LOG_LEVEL:-info}
export WS_SCRCPY_HOST=${WS_SCRCPY_HOST:-0.0.0.0}
export WS_SCRCPY_PORT=${WS_SCRCPY_PORT:-8000}
export WS_SCRCPY_PLAYER=${WS_SCRCPY_PLAYER:-mse}

# Set Android SDK environment variables
export ANDROID_SDK_ROOT=~/android-sdk
export PATH=$PATH:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin

cleanup() {
  echo "[run-local] Shutting down child processes"
  pkill -P $$ >/dev/null 2>&1 || true
}

trap cleanup EXIT

pushd "$BACKEND_DIR" >/dev/null
npm run dev &
BACKEND_PID=$!
popd >/dev/null

echo "[run-local] Backend PID $BACKEND_PID"

echo "[run-local] Expecting ws-scrcpy server at http://${WS_SCRCPY_HOST}:${WS_SCRCPY_PORT}/ (run npm start in ws-scrcpy repo)"

pushd "$FRONTEND_DIR" >/dev/null
npm run dev &
FRONTEND_PID=$!
popd >/dev/null

echo "[run-local] Frontend PID $FRONTEND_PID"

wait
