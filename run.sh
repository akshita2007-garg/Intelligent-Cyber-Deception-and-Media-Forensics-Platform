#!/usr/bin/env bash
# IDMF - start on Linux/macOS (needs Python 3.10+)
set -e
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  python3 -m venv .venv
  . .venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt
else
  . .venv/bin/activate
fi
echo "IDMF at http://127.0.0.1:8000  (investigator / forensics123)"
exec python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
