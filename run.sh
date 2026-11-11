#!/usr/bin/env bash
# Set up a virtualenv on first run, then start the app.
# Usage: ./run.sh [app.py args...]   e.g. ./run.sh --mode hidden_admin --reset
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "[*] Creating virtualenv in .venv (needs: sudo apt install python3-venv)"
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi

exec .venv/bin/python app.py "$@"
