import Encryption, base64, os, pathlib, sys, json, util, csv, io, threading, pyotp, zstandard as zstd, time
from PyQt6.QtWidgets import QApplication, QFileDialog, QMainWindow, QTableView, QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QInputDialog, QHeaderView, QProgressBar, QStyledItemDelegate
from PyQt6.QtCore import pyqtSignal, QAbstractTableModel, Qt, QModelIndex, QTimer, QMimeData
from PyQt6.QtGui import QFont, QIcon
from zxcvbn import zxcvbn
app=QApplication(sys.argv)
def show_message(parent, title, message, error=False):
    if error:QMessageBox.critical(parent, title, message)
    else:QMessageBox.warning(parent, title, message)
def EXIT(txt=''):
    print(txt)
    os.kill(os.getpid(),9)
file_path, _ = QFileDialog.getSaveFileName(None, "Create Password Manager File", os.path.expanduser('~/'), "Password Manager Files (*.pwmgr1)", options=QFileDialog.Option.DontConfirmOverwrite)
if not os.path.exists(os.path.dirname(file_path)):EXIT("Canceled")
app.setFont(QFont("Arial", 10))
if getattr(sys, "frozen", False):base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
else:base = os.path.dirname(os.path.abspath(__file__))
app.setWindowIcon(QIcon(os.path.join(base, "icon.png")))
if not file_path.endswith('.pwmgr1'):file_path+='.pwmgr1'
if not os.path.exists(file_path):pathlib.Path(file_path).touch()
def tocsv(data):
    output=io.StringIO()
    csv.writer(output).writerows(data)
    return output.getvalue()
def fromcsv(csv_string):return list(csv.reader(io.StringIO(csv_string)))
def save(data):
    try:
        while data[-1][:-1] == ["","","",""]:data.pop(-1)
    except:pass
    salt=os.urandom(64)
    keys=Encryption.gen_ed25519()
    encrypted_data=Encryption.encryptGCM(zstd.ZstdCompressor(level=19).compress(util.str_to_bytes(json.dumps({"data":tocsv(data),"prv":base64.b64encode(keys[0]).decode()}))), Encryption.kdf_slow(util.str_to_bytes(MASTER_PW),salt))
    signed_data=Encryption.ed25519_sign(keys[0],encrypted_data)
    encrypted=util.str_to_bytes(json.dumps({"salt":base64.b64encode(salt).decode(), "signed":base64.b64encode(signed_data).decode(), "pub":base64.b64encode(keys[1]).decode()}))
    del keys
    compressed=zstd.ZstdCompressor(level=19).compress(encrypted)
    if len(compressed)<len(encrypted):encrypted=compressed
    with open(file_path+'.tmp','wb') as f:f.write(encrypted);f.flush();os.fsync(f.fileno())
    os.replace(file_path+'.tmp',file_path)
def load():
    with open(file_path,'rb') as f:data=f.read()
    try:data=zstd.decompress(data)
    except:pass
    try:container=json.loads(util.bytes_to_str(data))
    except:
        save([])
        return []
    try:
        pub=base64.b64decode(container["pub"])
        signed=base64.b64decode(container["signed"])
        encrypted_data=Encryption.ed25519_verify(pub,signed)
    except Exception as e:
        show_message(None,"INVALID SIGNATURE",f"Vault integrity verification failed:\n{e}",True)
        EXIT("INVALID SIGNATURE")
    try:
        salt=base64.b64decode(container["salt"])
        data=Encryption.decryptGCM(encrypted_data, Encryption.kdf_slow(util.str_to_bytes(MASTER_PW),salt))
    except:
        show_message(None,"INCORRECT PASSWORD","Failed to decrypt",True)
        EXIT("INCORRECT PASSWORD")
    try:data=zstd.decompress(data)
    except:pass
    try:
        data=json.loads(util.bytes_to_str(data))
        prv=base64.b64decode(data["prv"])
        if not Encryption.validate_keys(prv,pub):
            show_message(None,"MALFORMED SAVE DATA", "private/public Key mismatch")
            EXIT("MALFORMED SAVE DATA")
        return fromcsv(data["data"])
    except Exception as e:
        show_message(None,"MALFORMED SAVE DATA",f"Failed to decode save data:\n{e}",True)
        EXIT("MALFORMED SAVE DATA")
class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login")
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Master Password:"))
        self.input = QLineEdit()
        self.input.setEchoMode(QLineEdit.EchoMode.Password)
        self.input.textChanged.connect(self.update_strength)
        layout.addWidget(self.input)
        self.strength = QProgressBar()
        self.strength.setRange(0, 1000)
        self.strength.setTextVisible(False)
        self.strength.setValue(0)
        layout.addWidget(self.strength)
        self.unlock_btn = QPushButton("Unlock")
        self.unlock_btn.clicked.connect(self.accept)
        layout.addWidget(self.unlock_btn)
        self.change_btn = QPushButton("Change Password")
        self.change_btn.clicked.connect(self.change_password)
        layout.addWidget(self.change_btn)
        self.setLayout(layout)
        self._change_requested = False
    def update_strength(self):
        try:
            result = zxcvbn(self.input.text())
            guesses = result["guesses_log10"]
            min_blue = 8.0
            max_blue = 10.0
            if guesses < min_blue:
                progress = (guesses / min_blue) * 500
                color = "red"
            elif guesses < max_blue:
                progress = 500 + ((guesses - min_blue) / (max_blue - min_blue)) * 500
                color = "#64C4FF"
            else:
                progress = 1000
                color = "green"
            progress = max(0, min(1000, progress))
            self.strength.setValue(int(progress))
            self.strength.setStyleSheet(f"""QProgressBar::chunk {{background-color: {color};}}""")
        except Exception:
            self.strength.setValue(0)
    def get_password(self):
        return self.input.text()
    def change_password(self):
        self._change_requested = True
        self.accept()
login = LoginDialog()
if login.exec() != QDialog.DialogCode.Accepted:EXIT()
MASTER_PW = login.get_password()
check=True
if getattr(login, "_change_requested", False):
    data = load()
    new_pw, ok = QInputDialog.getText(None, "Change Password", "Enter NEW master password:", QLineEdit.EchoMode.Password)
    if not ok or not new_pw:
        EXIT("Cancelled")
    MASTER_PW = new_pw
    result = zxcvbn(MASTER_PW)
    log_guesses = result["guesses_log10"]
    warnings = []
    suggestions = []
    if log_guesses < 10.0:
        warnings.append("A more secure password is advised (requires 10^10 guesses for max security).")
    if result["feedback"]["warning"]:
        warnings.append(result["feedback"]["warning"])
    suggestions = result["feedback"]["suggestions"]
    if len(warnings) + len(suggestions) > 0:
        msg = QMessageBox()
        msg.setWindowTitle("Password Strength Report")
        text = f"Score: {result['score']}/4\nLog10 Guesses: {log_guesses:.2f}\n\n"
        if warnings:
            text += "Warnings:\n" + "\n".join(warnings) + "\n\n"
        if suggestions:
            text += "Suggestions:\n" + "\n".join(suggestions)
        msg.setText(text)
        msg.exec()
    if log_guesses < 8.0:
        show_message(None,"Insecure Password","Password rejected: it does not provide sufficient security. A strong password should require at least 10⁸ guesses to crack.",True)
        EXIT("Insecure Password: Requires at least 10^8 guesses.")
        check = False
    save(data)
    QMessageBox.information(None, "Success", "Password changed successfully")
if check:
    result = zxcvbn(MASTER_PW)
    log_guesses = result["guesses_log10"]
    warnings = []
    suggestions = []
    if log_guesses < 10.0:
        warnings.append("A more secure password is advised.")
    if result["feedback"]["warning"]:
        warnings.append(result["feedback"]["warning"])
    suggestions = result["feedback"]["suggestions"]
    if len(warnings) + len(suggestions) > 0:
        msg = QMessageBox()
        msg.setWindowTitle("Password Strength Report")
        text = f"Score: {result['score']}/4\nLog10 Guesses: {log_guesses:.2f}\n\n"
        if warnings:
            text += "Warnings:\n" + "\n".join(warnings) + "\n\n"
        if suggestions:
            text += "Suggestions:\n" + "\n".join(suggestions)
        msg.setText(text)
        msg.exec()
    if log_guesses < 8.0:
        show_message(None,"Insecure Password","Password rejected: it does not provide sufficient security. A strong password should require at least 10⁸ guesses to crack.",True)
        EXIT("Insecure Password: Requires at least 10^8 guesses.")
class TotpDelegate(QStyledItemDelegate):
    def __init__(self, model, parent=None):
        super().__init__(parent)
        self.model = model
    def createEditor(self, parent, option, index):
        editor = super().createEditor(parent, option, index)
        if index.column() == self.model.TOTP_COL:self.model.begin_totp_edit(index.row())
        return editor
    def setModelData(self, editor, model, index):super().setModelData(editor, model, index)
    def destroyEditor(self, editor, index):
        if index.column() == self.model.TOTP_COL:self.model.end_totp_edit(index.row())
        super().destroyEditor(editor, index)
class AccountModel(QAbstractTableModel):
    data_changed_signal = pyqtSignal()
    HEADERS = ["Name", "Username", "Password", "Comments", "TOTP"]
    PASSWORD_COL = 2
    TOTP_COL = 4
    PASSWORD_VISIBLE_MS = 30_000
    TOTP_REFRESH_MS = 1_000
    DRAG_MIME = "application/x-pwmgr-row"

    def __init__(self, data=None):
        super().__init__()
        self._data = data or []
        n = len(self._data)
        self._visible = [False] * n
        self._totp_visible = [False] * n
        self._hide_timers = [None] * n
        self._totp_editing_rows = set()
        self._totp_timer = QTimer(self)
        self._totp_timer.setInterval(self.TOTP_REFRESH_MS)
        self._totp_timer.timeout.connect(self._refresh_visible_totps)
        self._totp_timer.start()

    def begin_totp_edit(self, row):
        if 0 <= row < len(self._data):
            self._totp_editing_rows.add(row)

    def end_totp_edit(self, row):
        self._totp_editing_rows.discard(row)
        if 0 <= row < len(self._data):
            index = self.index(row, self.TOTP_COL)
            self.dataChanged.emit(index, index)

    def rowCount(self, parent=QModelIndex()):
        return len(self._data) + 1

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def headerData(self, section, orientation, role):
        return self.HEADERS[section] if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal else None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        row, col = index.row(), index.column()

        if row >= len(self._data):
            return "" if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole) else None

        value = self._data[row][col]

        if role == Qt.ItemDataRole.EditRole:
            return 'Type "delete" 3 times' if col == self.TOTP_COL and value else value

        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if col == self.PASSWORD_COL:
            return value if self._visible[row] else "*****"

        if col == self.TOTP_COL:
            if not self._totp_visible[row]:
                return "*****"
            try:
                return pyotp.TOTP(value).now() if value else "*****"
            except Exception:
                return "*****"

        return value

    def flags(self, index):
        flags = Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsEditable | Qt.ItemFlag.ItemIsDropEnabled
        if index.isValid() and index.row() < len(self._data):
            flags |= Qt.ItemFlag.ItemIsDragEnabled
        return flags

    def supportedDropActions(self):
        return Qt.DropAction.MoveAction

    def supportedDragActions(self):
        return Qt.DropAction.MoveAction

    def mimeTypes(self):
        return [self.DRAG_MIME]

    def mimeData(self, indexes):
        mime = QMimeData()
        rows = {i.row() for i in indexes if i.isValid() and i.row() < len(self._data)}
        if len(rows) == 1:
            mime.setData(self.DRAG_MIME, str(next(iter(rows))).encode())
        return mime

    def dropMimeData(self, data, action, row, column, parent):
        if action != Qt.DropAction.MoveAction or not data.hasFormat(self.DRAG_MIME):
            return False

        try:
            src = int(bytes(data.data(self.DRAG_MIME)).decode())
        except (ValueError, UnicodeDecodeError):
            return False

        dst = parent.row() if row < 0 and parent.isValid() else row
        if dst < 0:
            dst = len(self._data)
        if src == dst:
            return False

        item = self._data.pop(src)
        visible = self._visible.pop(src)
        totp_visible = self._totp_visible.pop(src)
        timer = self._hide_timers.pop(src)

        was_editing = src in self._totp_editing_rows
        self._totp_editing_rows.discard(src)

        if dst > src:
            dst -= 1
        dst = max(0, min(dst, len(self._data)))

        self._data.insert(dst, item)
        self._visible.insert(dst, visible)
        self._totp_visible.insert(dst, totp_visible)
        self._hide_timers.insert(dst, timer)

        if was_editing:
            self._totp_editing_rows.add(dst)

        self.layoutChanged.emit()
        self.data_changed_signal.emit()
        return True

    def setData(self, index, value, role=Qt.ItemDataRole.EditRole):
        if not index.isValid() or role != Qt.ItemDataRole.EditRole:
            return False

        row, col = index.row(), index.column()

        if row >= len(self._data):
            self.beginInsertRows(QModelIndex(), len(self._data), len(self._data))
            self._data.append([""] * 5)
            self._visible.append(False)
            self._totp_visible.append(False)
            self._hide_timers.append(None)
            self.endInsertRows()

        if col == self.TOTP_COL and self._data[row][col]:
            if value.lower().count("delete") < 3:
                self.dataChanged.emit(index, index)
                return False
            self._data[row][col] = ""
        else:
            self._data[row][col] = value

        self.dataChanged.emit(index, index)
        self.data_changed_signal.emit()
        return True

    def set_data(self, data):
        self.beginResetModel()
        for timer in self._hide_timers:
            if timer is not None:
                timer.stop()
        n = len(data)
        self._data = data
        self._visible = [False] * n
        self._totp_visible = [False] * n
        self._hide_timers = [None] * n
        self._totp_editing_rows.clear()
        self.endResetModel()
        self.data_changed_signal.emit()

    def get_data(self):
        return self._data

    def toggle_password(self, row):
        try:
            timer = self._hide_timers[row]
            if timer is not None:
                timer.stop()
                timer.deleteLater()
                self._hide_timers[row] = None

            self._visible[row] = not self._visible[row]
            index = self.index(row, self.PASSWORD_COL)
            self.dataChanged.emit(index, index)

            if self._visible[row]:
                timer = QTimer(self)
                timer.setSingleShot(True)
                timer.setInterval(self.PASSWORD_VISIBLE_MS)
                timer.timeout.connect(lambda r=row: self._auto_hide_password(r))
                timer.start()
                self._hide_timers[row] = timer
        except (IndexError, RuntimeError):
            pass

    def _auto_hide_password(self, row):
        try:
            self._visible[row] = False
            self._hide_timers[row] = None
            index = self.index(row, self.PASSWORD_COL)
            self.dataChanged.emit(index, index)
        except (IndexError, RuntimeError):
            pass

    def toggle_totp(self, row):
        try:
            self._totp_visible[row] = not self._totp_visible[row]
            index = self.index(row, self.TOTP_COL)
            self.dataChanged.emit(index, index)
        except (IndexError, RuntimeError):
            pass

    def _refresh_visible_totps(self):
        if not any(self._totp_visible):
            return

        for row, visible in enumerate(self._totp_visible):
            if visible and row not in self._totp_editing_rows:
                index = self.index(row, self.TOTP_COL)
                self.dataChanged.emit(index, index)


AUTOSAVE_INTERVAL_MS = 45 * 1000
SESSION_TIMEOUT_MS = 15 * 60 * 1000

class TableEditor(QMainWindow):
    save_error_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.view = QTableView()
        self.setCentralWidget(self.view)
        self.model = AccountModel()
        self.view.setModel(self.model)

        # 1. Create and set delegate
        self.delegate = TotpDelegate(self.model, self.view)
        self.view.setItemDelegate(self.delegate)

        self.view.setDragEnabled(True)
        self.view.setAcceptDrops(True)
        self.view.setDropIndicatorShown(True)
        self.view.setDragDropMode(QTableView.DragDropMode.InternalMove)
        self.view.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.view.setDragDropOverwriteMode(False)
        self.view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.view.setSelectionMode(QTableView.SelectionMode.SingleSelection)

        header = self.view.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        for col in range(self.model.columnCount()):
            self.view.setColumnWidth(col, 180)

        self.status = self.statusBar()
        self._save_running = False
        self._save_again = False
        self._dirty = False

        # 2. Signal Connections
        self.save_error_signal.connect(self.show_save_error)
        self.view.clicked.connect(self.on_click)

        # Connect to self.delegate instead of self.view
        self.delegate.commitData.connect(self._editor_commit_data)
        self.delegate.closeEditor.connect(self._editor_closed)

        self.model.data_changed_signal.connect(self.mark_dirty)

        self.autosave_timer = QTimer(self)
        self.autosave_timer.setInterval(AUTOSAVE_INTERVAL_MS)
        self.autosave_timer.timeout.connect(self.autosave_tick)
        self.autosave_timer.start()

        self.session_timer = QTimer(self)
        self.session_timer.setSingleShot(True)
        self.session_timer.setInterval(SESSION_TIMEOUT_MS)
        self.session_timer.timeout.connect(self.close)
        self.session_timer.start()

        threading.Thread(target=self.load_worker, daemon=True).start()
    def _editor_commit_data(self, editor):
        index = self.view.currentIndex()
        if index.isValid() and index.column() == self.model.TOTP_COL:
            self.model.begin_totp_edit(index.row())

    def _editor_closed(self, editor, hint):
        index = self.view.currentIndex()
        if index.isValid() and index.column() == self.model.TOTP_COL:
            self.model.end_totp_edit(index.row())
    def load_worker(self):
        data = load()
        self.on_loaded(data)
        try:save(data)
        except Exception as e:self.save_error_signal.emit(str(e))

    def on_loaded(self, data):
        self.model.set_data(data);self._dirty = False

    def on_click(self, index):
        if index.column() == self.model.PASSWORD_COL:self.model.toggle_password(index.row())
        elif index.column() == self.model.TOTP_COL:self.model.toggle_totp(index.row())

    def mark_dirty(self):self._dirty = True

    def autosave_tick(self):
        if not self._dirty:return
        self._dirty = False
        if self._save_running:self._save_again = True
        else:self.start_save()

    def start_save(self):
        self._save_running = True
        self.status.showMessage("Saving...")
        self.setWindowTitle("Password Manager (Saving...)")
        threading.Thread(target=self.save_worker, daemon=True).start()

    def save_worker(self):
        try:save(self.model.get_data())
        except Exception as e:self.save_error_signal.emit(str(e))
        finally:self.save_done()

    def save_done(self):
        self._save_running = False
        self.status.clearMessage()
        self.setWindowTitle("Password Manager")
        if self._save_again:
            self._save_again = False
            self.start_save()

    def show_save_error(self, error):show_message(self, "Save Error", f"Could not save your data:\n\n{error}")

    def final_save(self,*args,**kwargs):
        self._save_running=True
        save(self.model.get_data())
        self._save_running=False

    def closeEvent(self, event):
        threading.Thread(target=self.final_save).start()
        event.accept()

window = TableEditor()
window.resize(900, 500)
window.show()
code=app.exec()
while window._save_running:time.sleep(1)
sys.exit(code)
