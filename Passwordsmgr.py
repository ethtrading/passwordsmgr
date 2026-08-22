#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Passwordsmgr - cross-platform (Linux / macOS / Windows) password keeper.

Data lives in vault.json next to this script. Every password is encrypted
with Fernet (AES-128-CBC + HMAC-SHA256); the key is derived from the master
password with PBKDF2-HMAC-SHA256 and a per-vault random salt.

On first run, when no vault.json exists, the app asks for a new master
password and creates an empty vault.

Run via ./launch.sh (creates a venv and installs requirements.txt), or:
    pip install -r requirements.txt && python3 Passwordsmgr.py
"""

import base64
import json
import os
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QGuiApplication, QPalette
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QDialog, QDialogButtonBox, QFormLayout,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPushButton, QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout,
    QWidget,
)

VAULT_FILE = Path(__file__).resolve().parent / "vault.json"
KDF_ITERATIONS = 600_000
VERIFIER_PLAINTEXT = b"passwordmgt-verifier-v1"
MIN_MASTER_PASSWORD_LEN = 8
PASSWORD_MASK = "\u2022" * 8
REVEAL_TIMEOUT_MS = 30_000      # auto-hide a revealed password after 30 s
CLIPBOARD_CLEAR_MS = 25_000     # clear a copied password after 25 s


# ---------------------------------------------------------------------------
# Vault: JSON storage + encryption
# ---------------------------------------------------------------------------

class WrongMasterPassword(Exception):
    pass


class Vault:
    def __init__(self, path):
        self.path = Path(path)
        self._fernet = None
        self.data = None

    # -- key handling -------------------------------------------------------

    @staticmethod
    def _derive_key(master_password, salt, iterations):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=salt, iterations=iterations)
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))

    def unlock(self, master_password):
        with open(self.path, encoding="utf-8") as f:
            self.data = json.load(f)
        kdf = self.data["kdf"]
        key = self._derive_key(master_password,
                               base64.b64decode(kdf["salt"]),
                               kdf["iterations"])
        fernet = Fernet(key)
        try:
            if fernet.decrypt(self.data["verifier"].encode()) != VERIFIER_PLAINTEXT:
                raise WrongMasterPassword()
        except InvalidToken:
            raise WrongMasterPassword()
        self._fernet = fernet

    def describe_problem(self):
        """Return a human-readable reason the vault file is unusable, else None."""
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except OSError as exc:
            return f"The file could not be opened ({exc.strerror})."
        except json.JSONDecodeError as exc:
            return f"The file is not valid JSON (line {exc.lineno})."
        if not isinstance(data, dict):
            return "The file does not contain a vault object."
        for key in ("kdf", "verifier", "records"):
            if key not in data:
                return f"The vault is missing its '{key}' section."
        if not isinstance(data["records"], list):
            return "The 'records' section is not a list."
        for key in ("salt", "iterations"):
            if key not in data.get("kdf", {}):
                return f"The vault is missing its 'kdf.{key}' value."
        return None

    def lock(self):
        self._fernet = None
        self.data = None

    @property
    def unlocked(self):
        return self._fernet is not None

    @classmethod
    def create_new(cls, path, master_password):
        """Create a fresh empty vault file protected by master_password."""
        salt = os.urandom(16)
        fernet = Fernet(cls._derive_key(master_password, salt, KDF_ITERATIONS))
        data = {
            "version": 1,
            "kdf": {"algo": "pbkdf2-sha256",
                    "iterations": KDF_ITERATIONS,
                    "salt": base64.b64encode(salt).decode("ascii")},
            "verifier": fernet.encrypt(VERIFIER_PLAINTEXT).decode("ascii"),
            "records": [],
        }
        vault = cls(path)
        vault.data = data
        vault._fernet = fernet
        vault.save()
        return vault

    # -- record operations --------------------------------------------------

    @property
    def records(self):
        return self.data["records"]

    def decrypt_password(self, record):
        return self._fernet.decrypt(record["password"].encode()).decode("utf-8")

    def _encrypt(self, plaintext):
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def add(self, platform, username, password):
        next_id = max((r["record_id"] for r in self.records), default=0) + 1
        self.records.append({
            "record_id": next_id,
            "platform": platform,
            "username": username,
            "password": self._encrypt(password),
        })
        self.save()

    def amend(self, record_id, platform, username, password=None):
        record = self._find(record_id)
        record["platform"] = platform
        record["username"] = username
        if password:  # empty/None means keep the existing password
            record["password"] = self._encrypt(password)
        self.save()

    def remove(self, record_id):
        self.data["records"] = [r for r in self.records
                                if r["record_id"] != record_id]
        self.save()

    def _find(self, record_id):
        for record in self.records:
            if record["record_id"] == record_id:
                return record
        raise KeyError(record_id)

    def save(self):
        """Atomic write so a crash mid-save cannot corrupt the vault."""
        tmp = self.path.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        os.replace(tmp, self.path)


# ---------------------------------------------------------------------------
# Reusable password field with a show/hide toggle
# ---------------------------------------------------------------------------

class PasswordEdit(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.toggle = QToolButton()
        self.toggle.setText("Show")
        self.toggle.setCheckable(True)
        self.toggle.toggled.connect(self._on_toggle)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.edit)
        layout.addWidget(self.toggle)

    def _on_toggle(self, checked):
        self.edit.setEchoMode(QLineEdit.EchoMode.Normal if checked
                              else QLineEdit.EchoMode.Password)
        self.toggle.setText("Hide" if checked else "Show")

    def text(self):
        return self.edit.text()

    def clear(self):
        self.edit.clear()
        self.toggle.setChecked(False)


# ---------------------------------------------------------------------------
# Dialogs
# ---------------------------------------------------------------------------

class UnlockDialog(QDialog):
    def __init__(self, vault, parent=None):
        super().__init__(parent)
        self.vault = vault
        self.setWindowTitle("Unlock Vault")
        self.setModal(True)
        self.setMinimumWidth(360)

        self.password = PasswordEdit()
        self.error = QLabel("")
        self.error.setStyleSheet("color: #ff7b72;")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                                   | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._try_unlock)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Enter your master password:"))
        layout.addWidget(self.password)
        layout.addWidget(self.error)
        layout.addWidget(buttons)
        self.password.edit.setFocus()
        self.password.edit.returnPressed.connect(self._try_unlock)

    def _try_unlock(self):
        try:
            self.vault.unlock(self.password.text())
            self.accept()
        except WrongMasterPassword:
            self.error.setText("Wrong master password - try again.")
            self.password.clear()
            self.password.edit.setFocus()


class NewVaultDialog(QDialog):
    """Shown on first run, when no vault file exists yet."""

    def __init__(self, parent=None, vault_path=None):
        super().__init__(parent)
        self.setWindowTitle("Create New Vault")
        self.setModal(True)
        self.setMinimumWidth(420)
        self.master_password = None
        self.vault_path = vault_path or VAULT_FILE

        self.pwd1 = PasswordEdit()
        self.pwd2 = PasswordEdit()
        self.error = QLabel("")
        self.error.setStyleSheet("color: #ff7b72;")

        form = QFormLayout()
        form.addRow("Master password:", self.pwd1)
        form.addRow("Confirm:", self.pwd2)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                                   | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._validate)
        buttons.rejected.connect(self.reject)

        intro = QLabel(
            f"No vault found, so a new empty one will be created at\n"
            f"{self.vault_path}\n\n"
            "Choose a master password. It is the only way to open the vault "
            "and it cannot be recovered or reset, so store it somewhere safe.")
        intro.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(form)
        layout.addWidget(self.error)
        layout.addWidget(buttons)

    def _validate(self):
        password = self.pwd1.text()
        if len(password) < MIN_MASTER_PASSWORD_LEN:
            self.error.setText("Master password must be at least "
                               f"{MIN_MASTER_PASSWORD_LEN} characters.")
            return
        if password != self.pwd2.text():
            self.error.setText("Passwords do not match.")
            return
        self.master_password = password
        self.accept()


class EditDialog(QDialog):
    """Add a new record, or amend an existing one when record is given."""

    def __init__(self, parent=None, record=None):
        super().__init__(parent)
        self.setWindowTitle("Amend Password" if record else "Add Password")
        self.setModal(True)
        self.setMinimumWidth(400)

        self.platform = QLineEdit()
        self.username = QLineEdit()
        self.password = PasswordEdit()
        if record:
            self.platform.setText(record["platform"])
            self.username.setText(record["username"])
            self.password.edit.setPlaceholderText("leave blank to keep current")

        form = QFormLayout()
        form.addRow("Platform:", self.platform)
        form.addRow("Username:", self.username)
        form.addRow("Password:", self.password)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                                   | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._validate)
        buttons.rejected.connect(self.reject)

        self.error = QLabel("")
        self.error.setStyleSheet("color: #ff7b72;")

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.error)
        layout.addWidget(buttons)
        self._is_amend = record is not None

    def _validate(self):
        if not self.platform.text().strip() or not self.username.text().strip():
            self.error.setText("Platform and username are required.")
            return
        if not self._is_amend and not self.password.text():
            self.error.setText("Password is required.")
            return
        self.accept()


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    COL_PLATFORM, COL_USERNAME, COL_PASSWORD = 0, 1, 2

    def __init__(self, vault):
        super().__init__()
        self.vault = vault
        self.revealed_id = None
        self.reveal_timer = QTimer(self)
        self.reveal_timer.setSingleShot(True)
        self.reveal_timer.timeout.connect(self.hide_password)

        self.setWindowTitle("Password Manager")
        self.resize(720, 560)
        self._build_ui()
        self.repopulate()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search platform or username...")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.apply_filter)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Platform", "Username", "Password"])
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSortingEnabled(True)
        # Without this the header's default indicator sorts platforms Z-to-A.
        self.table.sortByColumn(self.COL_PLATFORM, Qt.SortOrder.AscendingOrder)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.table.cellDoubleClicked.connect(self._on_double_click)

        self.btn_show = QPushButton("Show Password")
        self.btn_copy = QPushButton("Copy Password")
        self.btn_add = QPushButton("Add")
        self.btn_amend = QPushButton("Amend")
        self.btn_remove = QPushButton("Remove")
        self.btn_lock = QPushButton("Lock")

        self.btn_show.clicked.connect(self.toggle_password)
        self.btn_copy.clicked.connect(self.copy_password)
        self.btn_add.clicked.connect(self.add_record)
        self.btn_amend.clicked.connect(self.amend_record)
        self.btn_remove.clicked.connect(self.remove_record)
        self.btn_lock.clicked.connect(self.lock)

        buttons = QHBoxLayout()
        for b in (self.btn_show, self.btn_copy, self.btn_add,
                  self.btn_amend, self.btn_remove):
            buttons.addWidget(b)
        buttons.addStretch()
        buttons.addWidget(self.btn_lock)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        layout.addWidget(self.search)
        layout.addLayout(buttons)
        layout.addWidget(self.table)

        self.statusBar()

    # -- table population ----------------------------------------------------

    def repopulate(self):
        self.hide_password()
        header = self.table.horizontalHeader()
        sort_column = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        records = self.vault.records
        self.table.setRowCount(len(records))
        for row, record in enumerate(records):
            platform_item = QTableWidgetItem(record["platform"])
            platform_item.setData(Qt.ItemDataRole.UserRole, record["record_id"])
            self.table.setItem(row, self.COL_PLATFORM, platform_item)
            self.table.setItem(row, self.COL_USERNAME,
                               QTableWidgetItem(record["username"]))
            self.table.setItem(row, self.COL_PASSWORD,
                               QTableWidgetItem(PASSWORD_MASK))
        self.table.setSortingEnabled(True)
        self.table.sortItems(sort_column, sort_order)
        self.apply_filter()
        if records:
            self.statusBar().showMessage(f"{len(records)} records")
        else:
            self.statusBar().showMessage(
                "Vault is empty - click 'Add' to store your first password.")

    def apply_filter(self):
        needle = self.search.text().strip().lower()
        for row in range(self.table.rowCount()):
            platform = self.table.item(row, self.COL_PLATFORM).text().lower()
            username = self.table.item(row, self.COL_USERNAME).text().lower()
            visible = needle in platform or needle in username
            self.table.setRowHidden(row, not visible)

    # -- selection helpers ----------------------------------------------------

    def selected_row(self):
        rows = self.table.selectionModel().selectedRows()
        return rows[0].row() if rows else None

    def selected_record(self):
        row = self.selected_row()
        if row is None:
            return None
        record_id = self.table.item(row, self.COL_PLATFORM).data(
            Qt.ItemDataRole.UserRole)
        for record in self.vault.records:
            if record["record_id"] == record_id:
                return record
        return None

    def _row_of_record(self, record_id):
        for row in range(self.table.rowCount()):
            item = self.table.item(row, self.COL_PLATFORM)
            if item.data(Qt.ItemDataRole.UserRole) == record_id:
                return row
        return None

    # -- password reveal (one cell only) --------------------------------------

    def toggle_password(self):
        record = self.selected_record()
        if record is None:
            self.statusBar().showMessage("Select a row first.", 4000)
            return
        if self.revealed_id == record["record_id"]:
            self.hide_password()
        else:
            self.reveal_password(record)

    def reveal_password(self, record):
        self.hide_password()
        row = self._row_of_record(record["record_id"])
        if row is None:
            return
        self.table.item(row, self.COL_PASSWORD).setText(
            self.vault.decrypt_password(record))
        self.revealed_id = record["record_id"]
        self.btn_show.setText("Hide Password")
        self.reveal_timer.start(REVEAL_TIMEOUT_MS)

    def hide_password(self):
        if self.revealed_id is None:
            return
        row = self._row_of_record(self.revealed_id)
        if row is not None:
            self.table.item(row, self.COL_PASSWORD).setText(PASSWORD_MASK)
        self.revealed_id = None
        self.btn_show.setText("Show Password")
        self.reveal_timer.stop()

    def _on_selection_changed(self):
        record = self.selected_record()
        if self.revealed_id is not None and (
                record is None or record["record_id"] != self.revealed_id):
            self.hide_password()

    def _on_double_click(self, row, column):
        if column == self.COL_PASSWORD:
            self.toggle_password()

    # -- clipboard -------------------------------------------------------------

    def copy_password(self):
        record = self.selected_record()
        if record is None:
            self.statusBar().showMessage("Select a row first.", 4000)
            return
        password = self.vault.decrypt_password(record)
        QGuiApplication.clipboard().setText(password)
        self.statusBar().showMessage(
            f"Password for '{record['platform']}' copied - clipboard clears "
            f"in {CLIPBOARD_CLEAR_MS // 1000} s.", CLIPBOARD_CLEAR_MS)
        QTimer.singleShot(CLIPBOARD_CLEAR_MS,
                          lambda: self._clear_clipboard(password))

    @staticmethod
    def _clear_clipboard(expected):
        clipboard = QGuiApplication.clipboard()
        if clipboard.text() == expected:
            clipboard.clear()

    # -- add / amend / remove ---------------------------------------------------

    def add_record(self):
        dialog = EditDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.vault.add(dialog.platform.text().strip(),
                           dialog.username.text().strip(),
                           dialog.password.text())
            self.repopulate()

    def amend_record(self):
        record = self.selected_record()
        if record is None:
            self.statusBar().showMessage("Select a row to amend.", 4000)
            return
        dialog = EditDialog(self, record=record)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.vault.amend(record["record_id"],
                             dialog.platform.text().strip(),
                             dialog.username.text().strip(),
                             dialog.password.text())
            self.repopulate()

    def remove_record(self):
        record = self.selected_record()
        if record is None:
            self.statusBar().showMessage("Select a row to remove.", 4000)
            return
        answer = QMessageBox.question(
            self, "Remove Password",
            f"Remove the entry for '{record['platform']}' "
            f"(user '{record['username']}')?")
        if answer == QMessageBox.StandardButton.Yes:
            self.vault.remove(record["record_id"])
            self.repopulate()

    # -- locking ---------------------------------------------------------------

    def lock(self):
        self.hide_password()
        self.table.setRowCount(0)
        self.vault.lock()
        self.hide()
        dialog = UnlockDialog(self.vault)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.repopulate()
            self.show()
        else:
            QApplication.quit()


# ---------------------------------------------------------------------------

# Every colour is stated explicitly so the app looks identical regardless of
# the desktop theme (a system dark theme was turning button text white on white).
STYLESHEET = """
QWidget { color: #e9eaec; font-size: 13px; }
QMainWindow, QDialog, QMessageBox, QStatusBar { background: #23252a; }
QLabel { color: #e9eaec; background: transparent; }
QPushButton, QToolButton {
    color: #f2f3f5;
    background: #3a3e45;
    border: 1px solid #565b63;
    border-radius: 5px;
    padding: 6px 14px;
}
QPushButton:hover, QToolButton:hover { background: #474c55; border-color: #737a84; }
QPushButton:pressed, QToolButton:pressed,
QToolButton:checked { background: #2f6ea8; border-color: #4b8dd4; }
QPushButton:default { border-color: #4b8dd4; }
QLineEdit {
    color: #f2f3f5;
    background: #1a1c20;
    border: 1px solid #4a4e55;
    border-radius: 5px;
    padding: 6px 8px;
    selection-background-color: #2f6ea8;
    selection-color: #ffffff;
}
QLineEdit:focus { border-color: #4b8dd4; }
QTableWidget {
    color: #e9eaec;
    background: #1a1c20;
    alternate-background-color: #21242a;
    gridline-color: #32353b;
    border: 1px solid #3a3e45;
    border-radius: 5px;
    selection-background-color: #2f6ea8;
    selection-color: #ffffff;
}
QTableWidget::item { padding: 5px 6px; }
QHeaderView::section {
    color: #dfe1e4;
    background: #2e3138;
    padding: 7px 6px;
    border: none;
    border-right: 1px solid #23252a;
    border-bottom: 1px solid #23252a;
    font-weight: bold;
}
QStatusBar { color: #b3b7bd; }
QScrollBar:vertical, QScrollBar:horizontal { background: #1a1c20; border: none; }
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background: #4a4e55;
    border-radius: 5px;
    min-height: 24px;
    min-width: 24px;
}
QScrollBar::handle:hover { background: #5d626b; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
"""


def apply_dark_palette(app):
    """Fusion + palette so native widgets (message boxes, tooltips) match."""
    palette = QPalette()
    window, base, text = QColor("#23252a"), QColor("#1a1c20"), QColor("#e9eaec")
    palette.setColor(QPalette.ColorRole.Window, window)
    palette.setColor(QPalette.ColorRole.WindowText, text)
    palette.setColor(QPalette.ColorRole.Base, base)
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#21242a"))
    palette.setColor(QPalette.ColorRole.Text, text)
    palette.setColor(QPalette.ColorRole.Button, QColor("#3a3e45"))
    palette.setColor(QPalette.ColorRole.ButtonText, text)
    palette.setColor(QPalette.ColorRole.ToolTipBase, window)
    palette.setColor(QPalette.ColorRole.ToolTipText, text)
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#2f6ea8"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#8b9098"))
    palette.setColor(QPalette.ColorGroup.Disabled,
                     QPalette.ColorRole.Text, QColor("#7b8088"))
    palette.setColor(QPalette.ColorGroup.Disabled,
                     QPalette.ColorRole.ButtonText, QColor("#7b8088"))
    app.setPalette(palette)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Password Manager")
    app.setStyle("Fusion")
    apply_dark_palette(app)
    app.setStyleSheet(STYLESHEET)

    vault = Vault(VAULT_FILE)

    if not VAULT_FILE.exists():
        dialog = NewVaultDialog(vault_path=VAULT_FILE)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)
        try:
            vault = Vault.create_new(VAULT_FILE, dialog.master_password)
        except OSError as exc:
            QMessageBox.critical(None, "Cannot create vault",
                                 f"Could not write {VAULT_FILE}:\n\n{exc}")
            sys.exit(1)
    else:
        problem = vault.describe_problem()
        if problem:
            QMessageBox.critical(
                None, "Cannot read vault",
                f"{VAULT_FILE.name} exists but cannot be used:\n\n{problem}\n\n"
                "Restore it from a backup, or move it aside to start a new vault.")
            sys.exit(1)
        dialog = UnlockDialog(vault)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)

    window = MainWindow(vault)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
