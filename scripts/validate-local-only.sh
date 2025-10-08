#!/usr/bin/env bash
set -euo pipefail

PORTS=(7070 8080 8000)

collect_listeners() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltn | tail -n +2
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn | tail -n +3
  else
    echo "[validate-local-only] ERROR: neither ss nor netstat available" >&2
    exit 1
  fi
}

validate_port() {
  local port=$1
  local matched=0

  while IFS= read -r line; do
    [[ -z $line ]] && continue
    # Normalize fields: last but one column holds the local address in both ss and netstat outputs
    local addr
    addr=$(awk '{print $(NF-1)}' <<<"$line")

    if [[ $addr == *":$port" ]]; then
      matched=1
      if [[ $addr != 127.0.0.1:* && $addr != ::1:* ]]; then
        echo "[validate-local-only] ERROR: port $port bound to non-local address: $addr" >&2
        exit 1
      fi
    fi
  done < <(collect_listeners)

  if [[ $matched -eq 0 ]]; then
    echo "[validate-local-only] Warning: no listeners detected on port $port"
  else
    echo "[validate-local-only] Port $port bound exclusively to localhost"
  fi
}

for port in "${PORTS[@]}"; do
  validate_port "$port"
done

echo "[validate-local-only] Validation complete"
