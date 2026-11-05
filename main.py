import sys

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QDialog,
    QVBoxLayout, QHBoxLayout, QFormLayout,
    QPushButton, QLabel, QMessageBox,
    QLineEdit, QSpinBox, QDialogButtonBox
)
from PyQt5.QtCore import QSettings, Qt, QThread, pyqtSignal, QTimer

from pymobiledevice3.lockdown import create_using_usbmux

from exploits import get_exploit
from exploits.common import parse_version
from exploits.itunesstored.itunesstored import (
    DEFAULT_ATTEMPTS, DEFAULT_BACKEND_URL, MAX_ATTEMPTS,
    ItunesstoredExploit, validate_backend_url
)


def load_settings():
    settings = QSettings()
    try:
        attempts = int(settings.value('attempts', DEFAULT_ATTEMPTS, int))
    except (TypeError, ValueError):
        attempts = DEFAULT_ATTEMPTS

    return {
        'backend_url': settings.value('backend_url', DEFAULT_BACKEND_URL, str),
        'attempts': min(MAX_ATTEMPTS, max(1, attempts)),
    }


def save_settings(settings):
    out = QSettings()
    out.setValue('backend_url', settings['backend_url'])
    out.setValue('attempts', settings['attempts'])


class SettingsDialog(QDialog):
    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Settings')

        self.backend_url = QLineEdit(settings['backend_url'])
        self.backend_url.setPlaceholderText(DEFAULT_BACKEND_URL)
        self.backend_url.setMinimumWidth(320)
        self.backend_note = QLabel(
            'HTTPS is recommended. HTTP is unencrypted; legacy iOS versions may '
            'require a backend certificate they already trust.'
        )
        self.backend_note.setWordWrap(True)

        self.attempts = QSpinBox()
        self.attempts.setRange(1, MAX_ATTEMPTS)
        self.attempts.setValue(settings['attempts'])

        layout = QFormLayout(self)
        layout.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        layout.addRow(QLabel('<b>itunesstored</b>'))
        layout.addRow('Backend URL:', self.backend_url)
        layout.addRow(self.backend_note)
        layout.addRow('Attempts:', self.attempts)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def values(self):
        return {
            'backend_url': self.backend_url.text().strip() or DEFAULT_BACKEND_URL,
            'attempts': self.attempts.value(),
        }

    def accept(self):
        try:
            validate_backend_url(self.values()['backend_url'])
        except ValueError as exc:
            QMessageBox.warning(self, 'Invalid backend URL', str(exc))
            return
        super().accept()


class ActivationThread(QThread):
    status = pyqtSignal(str)
    success = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, settings):
        super().__init__()
        self.settings = settings

    def run(self):
        try:
            lockdown = create_using_usbmux()
            values = lockdown.get_value()

            if values.get('ActivationState') == 'Activated':
                self.success.emit('Device is already activated')
                return

            exploit_cls = get_exploit(parse_version(values.get('ProductVersion')), lockdown.udid)
            if exploit_cls is None:
                self.error.emit('Unsupported iOS version')
                return

            self.status.emit('Activating device...')
            exploit_cls(log=self.status.emit, **self.settings).run(lockdown)
            self.success.emit('Done!')

        except TimeoutError:
            self.error.emit(
                'Device did not reconnect in time. Please ensure it is connected and try again.'
            )
        except Exception as e:
            self.error.emit(repr(e))


class DevicePollThread(QThread):
    result = pyqtSignal(object)

    def __init__(self, settings, settings_revision):
        super().__init__()
        self.settings = dict(settings)
        self.settings_revision = settings_revision

    def emit_result(self, result):
        result['settings_revision'] = self.settings_revision
        self.result.emit(result)

    def run(self):
        try:
            lockdown = create_using_usbmux()
            values = lockdown.get_value()
            product = values.get('ProductType') or 'Unknown device'
            version = values.get('ProductVersion')
            build = values.get('BuildVersion')

            if values.get('ActivationState') == 'Activated':
                self.emit_result({
                    'text': f'{product} is already activated',
                    'enabled': False,
                    'version': None,
                    'method': None,
                })
                return
            if not version:
                raise ValueError('The connected device did not report its iOS version')

            version_tuple = parse_version(version)
            exploit_cls = get_exploit(version_tuple, lockdown.udid)
        except Exception as exc:
            self.emit_result({
                'text': f'Could not read a device over USB: {exc}',
                'enabled': False,
                'version': None,
                'method': None,
            })
            return

        if exploit_cls is None:
            self.emit_result({
                'text': f'Unsupported {product} iOS version: {version}',
                'enabled': False,
                'version': None,
                'method': None,
            })
            return

        try:
            supported = exploit_cls.available(
                product, build, lockdown.udid, **self.settings
            )
        except Exception as exc:
            self.emit_result({
                'text': f'Could not check device support: {exc}',
                'enabled': False,
                'version': None,
                'method': None,
            })
            return

        if not supported:
            self.emit_result({
                'text': exploit_cls.unavailable.format(product=product, version=version),
                'enabled': False,
                'version': None,
                'method': None,
            })
            return

        self.emit_result({
            'text': f'Connected: {product} ({version}, build {build or "unknown"})',
            'enabled': True,
            'version': version_tuple,
            'method': exploit_cls.name,
        })


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('hacktiv8 v1.2.2')
        self.setFixedSize(500, 200)

        self.version = (0,)
        self.method = None
        self.settings = load_settings()
        self.settings_revision = 0
        self.poll_worker = None

        self.status = QLabel('No device connected')
        self.status.setWordWrap(True)
        self.activate = QPushButton('Activate Device')
        self.activate.setEnabled(False)

        self.settings_btn = QPushButton('\u2699')
        self.settings_btn.setFixedWidth(36)
        self.settings_btn.setToolTip('Settings')
        self.settings_btn.clicked.connect(self.open_settings)

        row = QHBoxLayout()
        row.setSpacing(4)
        row.addWidget(self.activate)
        row.addWidget(self.settings_btn)

        layout = QVBoxLayout()
        layout.addWidget(self.status)
        layout.addLayout(row)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.activate.clicked.connect(self.start_activation)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll_device)
        self.timer.start(1000)

    def poll_device(self):
        if self.poll_worker is not None and self.poll_worker.isRunning():
            return
        self.poll_worker = None

        self.activate.setEnabled(False)
        self.status.setText('Checking connected device…')
        self.poll_worker = DevicePollThread(self.settings, self.settings_revision)
        self.poll_worker.result.connect(self.on_device_poll_result)
        self.poll_worker.finished.connect(self.on_device_poll_finished)
        self.poll_worker.start()

    def on_device_poll_result(self, result):
        if result['settings_revision'] != self.settings_revision:
            return
        self.version = result.get('version') or (0,)
        self.method = result.get('method')
        self._set_state(result['text'], result['enabled'])

    def on_device_poll_finished(self):
        if self.sender() is self.poll_worker:
            self.poll_worker = None

    def _set_state(self, text, enabled):
        self.status.setText(text)
        self.activate.setEnabled(enabled)

    def open_settings(self):
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec_() == QDialog.Accepted:
            try:
                candidate = dialog.values()
                validate_backend_url(candidate['backend_url'])
            except ValueError as exc:
                QMessageBox.warning(self, 'Invalid settings', str(exc))
                return
            self.settings = candidate
            save_settings(self.settings)
            self.settings_revision += 1
            self.version = (0,)
            self.method = None
            self._set_state('Settings saved; checking the connected device…', False)

    def start_activation(self):
        if self.poll_worker is not None and self.poll_worker.isRunning():
            self.status.setText('Still checking the connected device. Please wait.')
            return

        if self.method == 'itunesstored':
            notes = [
                'Keep the device and this computer connected to Wi-Fi.',
                'The procedure replaces Downloads/downloads.28.sqlitedb; other '
                'files in Downloads are preserved.',
            ]
        else:
            notes = ['The procedure changes activation-related system data and reboots the device.']
            if (8,) <= self.version <= (8, 4, 1):
                notes.append(
                    'On some cellular iOS 8 devices, cellular service is disabled '
                    'during this procedure.'
                )

        try:
            backend_url = validate_backend_url(self.settings['backend_url'])
            if backend_url.lower().startswith('http://') and self.method == 'itunesstored':
                notes.append('The configured backend uses unencrypted HTTP.')
        except ValueError:
            notes.append('The configured backend URL is invalid; review Settings before continuing.')

        notes.append(
            'This tool does not remove an Apple Account or Activation Lock from Apple servers.'
        )
        response = QMessageBox.warning(
            self,
            'Review device changes',
            'Continue only if you control this device and accept these changes:\n\n'
            + '\n'.join(f'• {note}' for note in notes),
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if response != QMessageBox.Yes:
            return

        self.timer.stop()
        self.activate.setEnabled(False)

        self.worker = ActivationThread(self.settings)
        self.worker.status.connect(self.status.setText)
        self.worker.success.connect(self.on_success)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_success(self, msg):
        self.status.setText(msg)
        QMessageBox.information(self, 'Success', msg)
        self.activate.setEnabled(False)
        self.timer.start(1000)

    def on_error(self, msg):
        QMessageBox.critical(self, 'Error', msg)
        self.status.setText('Error occurred')
        self.activate.setEnabled(False)
        self.timer.start(1000)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
