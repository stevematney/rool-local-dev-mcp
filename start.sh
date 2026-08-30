#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

NGROK_URL="https://gumming-jersey-rewash.ngrok-free.dev"
PORT=${PORT:-8000}

echo "[start] booting mcp_fs_server on :${PORT} ..."
python mcp_fs_server.py &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT

# wait for the server to accept connections (IPv4+IPv6 safe)
for i in $(seq 1 50); do
  if curl -fsS -m 2 "http://localhost:${PORT}/health" >/dev/null 2>&1; then
    echo "[start] server up."
    break
  fi
  sleep 0.2
done

if ! curl -fsS -m 2 "http://localhost:${PORT}/health" >/dev/null 2>&1; then
  echo "[start] ERROR: server did not come up on :${PORT}" >&2
  exit 1
fi

echo "[start] starting ngrok → ${NGROK_URL}"
exec ngrok http "${PORT}" --url="${NGROK_URL}"
