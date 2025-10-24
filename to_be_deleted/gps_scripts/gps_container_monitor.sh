#!/bin/bash

# GPS Container Monitor Script
# Monitors and restarts GPS daemon inside Docker container

set -euo pipefail

CONTAINER_ID="3c75e7304ff6"
GPS_SETUP_SCRIPT="/home/blhack/project/Apptest/scripts/auto_gps_setup.sh"
MONITOR_INTERVAL=30  # Check every 30 seconds
LOG_FILE="/tmp/gps_monitor.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] GPS Monitor: $*" | tee -a "$LOG_FILE"
}

check_container_running() {
    if sudo docker exec -i "$CONTAINER_ID" echo "container ok" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

check_gps_daemon_running() {
    # Check if GPS daemon is running inside container
    local daemon_pid
    daemon_pid=$(sudo docker exec -i "$CONTAINER_ID" cat /tmp/gps_control/daemon.pid 2>/dev/null || echo "")

    if [ -n "$daemon_pid" ]; then
        # Check if process with that PID is actually running
        if sudo docker exec -i "$CONTAINER_ID" ps -p "$daemon_pid" >/dev/null 2>&1; then
            return 0
        fi
    fi

    return 1
}

restart_gps_daemon() {
    log "Restarting GPS daemon..."

    # Run GPS setup script to restart daemon
    if "$GPS_SETUP_SCRIPT" >/dev/null 2>&1; then
        log "GPS daemon restarted successfully"
        return 0
    else
        log "Failed to restart GPS daemon"
        return 1
    fi
}

main() {
    log "Starting GPS container monitor (PID: $$, Interval: ${MONITOR_INTERVAL}s)"

    while true; do
        # Check if container is running
        if ! check_container_running; then
            log "Container not running, waiting..."
            sleep "$MONITOR_INTERVAL"
            continue
        fi

        # Check if GPS daemon is running
        if ! check_gps_daemon_running; then
            log "GPS daemon not running in container"
            restart_gps_daemon
        else
            log "GPS daemon is running (checked at $(date '+%H:%M:%S'))"
        fi

        sleep "$MONITOR_INTERVAL"
    done
}

# Start monitoring
main "$@"