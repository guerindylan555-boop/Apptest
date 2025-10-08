#!/usr/bin/env bash
set -euo pipefail

# This script provisions the Android SDK components and creates the rooted
# autoapp-local AVD required for the local-only emulator stack.

AVD_NAME="autoapp-local"
PACKAGE="system-images;android-34;google_apis;x86_64"
SDKMANAGER=${SDKMANAGER:-"sdkmanager"}
AVDMANAGER=${AVDMANAGER:-"avdmanager"}
EMULATOR=${EMULATOR:-"emulator"}

log() {
  printf '[setup-avd] %s\n' "$*"
}

ensure_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command '$1' not found in PATH" >&2
    exit 1
  fi
}

main() {
  ensure_command "$SDKMANAGER"
  ensure_command "$AVDMANAGER"
  ensure_command "$EMULATOR"

  log "Installing required system image: $PACKAGE"
  yes | "$SDKMANAGER" --install "$PACKAGE" > /dev/null

  if "$AVDMANAGER" list avd | grep -q "$AVD_NAME"; then
    log "AVD '$AVD_NAME' already exists; skipping creation"
  else
    log "Creating AVD '$AVD_NAME'"
    echo "no" | "$AVDMANAGER" create avd \
      --name "$AVD_NAME" \
      --package "$PACKAGE" \
      --device pixel_6 \
      --force
  fi

  log "AVD setup complete"
}

main "$@"
