#!/usr/bin/env bash
# start.sh — the one entry point for running the server.
# Startup scope lives here (venv setup, env checks, tunnel), not in launcher.py.
# Small, simple steps: validate everything first, then start.
set -euo pipefail

die() { echo "start.sh: $*" >&2; exit 1; }

# --- validate configuration before doing anything ---
[ -f .env ] || die "no .env found — copy .env.example and fill it in"

set -a; # shellcheck disable=SC1091
source .env; set +a

: "${PORT:=8000}"
: "${NGROK_URL:?NGROK_URL must be set in .env}"
case "$NGROK_URL" in
  *your-subdomain*|*your-tunnel*) die "NGROK_URL is still the .env.example placeholder" ;;
esac
command -v ngrok >/dev/null || die "ngrok not found on PATH"

# --- build the venv if needed ---
if [ ! -x .venv/bin/python ]; then
    python -m venv .venv
    ./.venv/bin/pip install -r requirements.txt
fi

exec ./.venv/bin/python ./app/launcher.py
