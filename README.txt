# Passwordsmgr

Cross-platform password keeper (Linux, macOS, and Windows). Passwords live in `vault.json` next to the app, encrypted with PBKDF2-HMAC-SHA256 + Fernet.

## Run

### Linux / macOS

```bash
chmod +x launch.sh
./launch.sh
```

### Windows (cmd.exe / PowerShell)

Double-click `launch.bat`, or run it from a terminal:

```bat
launch.bat
```

### Windows (Git Bash / WSL)

```bash
./launch.sh
```

`launch.sh` (or `launch.bat` on Windows) creates a `venv`, installs `requirements.txt` (PySide6, cryptography), and starts the app.

Or, if the packages are already on your system Python:

```bash
python3 Passwordsmgr.py          # Linux / macOS
python Passwordsmgr.py           # Windows
```

Python 3.9+ is required. On a new machine: `python3 -m pip install -r requirements.txt` (or `python -m pip install -r requirements.txt` on Windows).

## First run

If `vault.json` is missing, the app asks for a new master password (at least 8 characters, confirmed twice) and creates an empty vault. That password cannot be recovered or reset.

Copy the whole folder to another machine to take the vault with you. Unlock with the same master password.

## Using it

- Search filters by platform or username.
- **Show Password** (or double-click the password cell) reveals only the selected row. It hides again when you select another row, click Hide, or after 30 seconds.
- **Copy Password** copies the decrypted password without showing it. The clipboard is cleared after 25 seconds.
- **Add / Amend / Remove** — Amend and Remove use the selected row. Leave the password blank when amending to keep the current one.
- **Lock** closes the vault and asks for the master password again.

Password fields hide what you type. Use **Show** next to a field if you need to check it.

## Storage

`vault.json` is the only data file. Each password is a Fernet token; the key is derived from your master password and a random salt stored in the file (600,000 PBKDF2 iterations). A wrong master password is rejected immediately.

Keep a backup of `vault.json`. Do not share it. It is excluded from git via `.gitignore`.

## Command shortcut

Launch it by typing `PasswordManager` in a terminal. `launch.sh` resolves symlinks, so the link can live anywhere on your `PATH`.

### Linux

```bash
mkdir -p ~/.local/bin
ln -sf /home/ml/Application/PasswordManager/launch.sh ~/.local/bin/PasswordManager
```

Make sure `~/.local/bin` is on your `PATH`. Check with `echo $PATH`. If it is missing, add this to `~/.bashrc` (or `~/.profile`) and open a new terminal:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### macOS

`/usr/local/bin` (and `/opt/homebrew/bin` on Apple Silicon) are usually on `PATH` already:

```bash
ln -s /Users/michael/AnacondaProjects/git/passwordsmgr/launch.sh /usr/local/bin/PasswordManager
```

If `/usr/local/bin` is not writable (owned by root), use a user-writable `PATH` directory instead, e.g.:

```bash
mkdir -p ~/.local/bin
ln -s /Users/michael/AnacondaProjects/git/passwordsmgr/launch.sh ~/.local/bin/PasswordManager
export PATH="$HOME/.local/bin:$PATH"   # add to ~/.zshrc
```

### Windows

Put `launch.bat` in a folder on your `PATH`, or create a small `PasswordManager.cmd` that calls it:

```bat
@echo off
call "C:\path\to\passwordsmgr\launch.bat"
```

To point an existing `PasswordManager` command at this app instead, find it with `which PasswordManager` then `ls -l $(which PasswordManager)`, and replace that link (or edit that script) to run `launch.sh`.
