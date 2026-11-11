#!/usr/bin/env bash
# Set up a virtualenv (if needed) and keep its dependencies in sync, then
# start the app. Usage: ./run.sh [app.py args...]  e.g. ./run.sh --mode hidden_admin --reset
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
  echo "[*] Creating virtualenv in .venv (needs: sudo apt install python3-venv)"
  python3 -m venv .venv
fi

# Always run this (not just on first create): cheap no-op when already
# installed, and it recovers on its own if an earlier run of this script
# was interrupted partway through setup, or requirements.txt changed.
.venv/bin/pip install -q -r requirements.txt

exec .venv/bin/python app.py "$@"
