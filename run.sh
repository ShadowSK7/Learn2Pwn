#!/usr/bin/env bash
# Set up a virtualenv (if needed) and start the app.
# Usage: ./run.sh [app.py args...]  e.g. ./run.sh --mode hidden_admin --reset
set -euo pipefail
cd "$(dirname "$0")"

# Checks that Flask is actually importable, not just that pip once said it
# installed it - catches a partial/interrupted install, a venv whose base
# Python changed under it, or files corrupted by an earlier unclean
# shutdown, all of which otherwise look fine until you try to import them.
venv_is_usable() {
  [ -x .venv/bin/python ] && .venv/bin/python -c "from flask import Flask" >/dev/null 2>&1
}

if ! venv_is_usable; then
  echo "[*] (Re)creating virtualenv in .venv (needs: sudo apt install python3-venv)"
  rm -rf .venv
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi

exec .venv/bin/python app.py "$@"
