#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
    echo "[start] creating virtual environment..."
    python -m venv .venv
    PIP_USER=0 ./.venv/bin/pip install -r requirements.txt
fi

source .venv/bin/activate
exec python ./app/launcher.py
