#!/usr/bin/env bash
# Launch the password manager inside a local virtualenv.
# Works on Linux, macOS, and Windows (Git Bash / MSYS2 / Cygwin / WSL).
# First run creates the venv and installs dependencies.
set -e

# Resolve the real location of this script so it also works when invoked
# through a symlink on PATH (e.g. PasswordManager -> launch.sh).
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    case "$SOURCE" in
        /*) ;;
        *) SOURCE="$DIR/$SOURCE" ;;
    esac
done
cd "$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"

APP="Passwordsmgr.py"

# Windows (Git Bash / MSYS2 / Cygwin) uses a different venv layout
# (Scripts/ instead of bin/) and usually exposes Python as `py` or
# `python` rather than `python3`.
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=1 ;;
    *) IS_WINDOWS=0 ;;
esac

if [ "$IS_WINDOWS" = "1" ]; then
    VENV_PY="venv/Scripts/python.exe"
    if command -v py >/dev/null 2>&1; then
        PYTHON="${PYTHON:-py -3}"        # Python launcher (recommended)
    else
        PYTHON="${PYTHON:-python}"
    fi
else
    VENV_PY="venv/bin/python"
    PYTHON="${PYTHON:-python3}"
fi

# `PYTHON` may be multi-word (e.g. "py -3"); check only its first word.
PY_CMD="${PYTHON%% *}"
if ! command -v "$PY_CMD" >/dev/null 2>&1; then
    echo "ERROR: Python 3 not found. Install it from https://www.python.org/downloads/," >&2
    echo "       or set PYTHON=/path/to/python3 (or PYTHON='py -3' on Windows)." >&2
    exit 1
fi

if [ ! -d venv ]; then
    echo "Creating virtual environment..."
    $PYTHON -m venv venv
    "$VENV_PY" -m pip install --upgrade pip
fi

# Runs every time so an interrupted first install completes on the next launch.
if ! "$VENV_PY" -c "import PySide6, cryptography" >/dev/null 2>&1; then
    echo "Installing dependencies..."
    "$VENV_PY" -m pip install -r requirements.txt
fi

exec "$VENV_PY" "$APP"
