#!/usr/bin/env bash
# LEGACY: retained only for reference. Runtime now uses the Dockploy-managed emulator.
# Wrapper script to launch Android emulator with proper environment

export ANDROID_SDK_ROOT="${HOME}/Android"
export ANDROID_HOME="${HOME}/Android"
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH="$PATH:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools:${ANDROID_SDK_ROOT}/emulator"
export LD_LIBRARY_PATH="${ANDROID_SDK_ROOT}/emulator/lib64:${LD_LIBRARY_PATH:-}"

# For headless VPS operation - suppress Qt warnings and ensure software rendering
export QT_QPA_PLATFORM=offscreen
export QT_LOGGING_RULES="*.debug=false;qt.qpa.*=false"
export LIBGL_ALWAYS_SOFTWARE=1

# Log for debugging
echo "$(date): Launching emulator with args: $@" >> /tmp/emulator-wrapper.log
echo "Environment: ANDROID_SDK_ROOT=$ANDROID_SDK_ROOT JAVA_HOME=$JAVA_HOME" >> /tmp/emulator-wrapper.log

exec "${ANDROID_SDK_ROOT}/emulator/emulator" "$@"
