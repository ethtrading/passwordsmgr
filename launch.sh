#!/usr/bin/env bash
# Launch the password manager inside a local virtualenv.
# Works on Linux and macOS. First run creates the venv and installs deps.
set -e
cd "$(dirname "$0")"

APP="Passwordsmgr.py"
PYTHON="${PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "ERROR: '$PYTHON' not found. Install Python 3, or set PYTHON=/path/to/python3." >&2
    exit 1
fi

if [ ! -d venv ]; then
    echo "Creating virtual environment..."
    "$PYTHON" -m venv venv
    ./venv/bin/pip install --upgrade pip
fi

# Runs every time so an interrupted first install completes on the next launch.
if ! ./venv/bin/python -c "import PySide6, cryptography" >/dev/null 2>&1; then
    echo "Installing dependencies..."
    ./venv/bin/pip install -r requirements.txt
fi

exec ./venv/bin/python "$APP"
