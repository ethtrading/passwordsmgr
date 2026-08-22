@echo off
rem Launch the password manager inside a local virtualenv (native Windows:
rem cmd.exe or PowerShell). Creates the venv and installs dependencies
rem on first run. Use launch.sh instead when running under Git Bash / WSL.
setlocal
cd /d "%~dp0"

set "APP=Passwordsmgr.py"
set "VENV_PY=venv\Scripts\python.exe"

rem Pick a Python interpreter: the `py` launcher first, then `python`.
set "PYTHON="
where py >nul 2>nul && set "PYTHON=py -3"
if not defined PYTHON where python >nul 2>nul && set "PYTHON=python"
if not defined PYTHON (
    echo ERROR: Python 3 not found. Install it from https://www.python.org/downloads/
    exit /b 1
)

if not exist "venv" (
    echo Creating virtual environment...
    %PYTHON% -m venv venv
    "%VENV_PY%" -m pip install --upgrade pip
)

rem Runs every time so an interrupted first install completes on the next launch.
"%VENV_PY%" -c "import PySide6, cryptography" >nul 2>nul
if errorlevel 1 (
    echo Installing dependencies...
    "%VENV_PY%" -m pip install -r requirements.txt
)

"%VENV_PY%" "%APP%"
endlocal
