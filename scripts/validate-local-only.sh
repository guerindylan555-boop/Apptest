#!/usr/bin/env bash
set -euo pipefail

PORTS=(8080 8081 5173)

validate_port() {
  local port=$1
  local entries
  if command -v ss >/dev/null 2>&1; then
    entries=$(ss -ltn sport = :"$port" | tail -n +2 || true)
  else
    entries=$(netstat -ltn | grep ":$port" || true)
  fi

  if [[ -z "$entries" ]]; then
    echo "[validate-local-only] Warning: no listeners found on port $port"
    return
  fi

  while read -r line; do
    [[ -z "$line" ]] && continue
    local addr
    addr=$(echo "$line" | awk '{print $(NF-1)}')
    if [[ "$addr" != 127.0.0.1:* && "$addr" != ::1:* ]]; then
      echo "[validate-local-only] ERROR: port $port bound to non-local address: $addr" >&2
      exit 1
    fi
  done <<< "$entries"

  echo "[validate-local-only] Port $port bound to localhost"
}

for port in "${PORTS[@]}"; do
  validate_port "$port"
fi

echo "[validate-local-only] All specified ports scoped to localhost"
