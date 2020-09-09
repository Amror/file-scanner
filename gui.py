import sys
import os.path
import filereport
import asyncio
import aiohttp
from re import findall
from datetime import datetime
from PyQt5.QtGui import QIcon
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QLineEdit, QPlainTextEdit, QFileDialog, QInputDialog, QCheckBox


class MainWindow(QMainWindow):

    def __init__(self,
                 x: int = 760,
                 y: int = 300,
                 width: int = 400,
                 height: int = 520) -> None:
        super().__init__()
        self.setFixedSize(width, height)
        self.move(x, y)
        self.setWindowTitle('File Scanner')
        self.setWindowIcon(QIcon('imgs/icon.png'))
        self.api_key = ''
        self.initUI()

    def initUI(self) -> None:
        """Creates the program main widgets"""

        # File select button
        self.b1 = QtWidgets.QPushButton(self)
        self.b1.setText('Select File')
        self.b1.setGeometry(80, 320, 100, 30)
        self.b1.clicked.connect(lambda: self.get_path(True))

        # Folder select button
        self.b2 = QtWidgets.QPushButton(self)
        self.b2.setText('Select Folder')
        self.b2.setGeometry(210, 320, 100, 30)
        self.b2.clicked.connect(lambda: self.get_path(False))

        # Scan output textbox
        self.textbox = QPlainTextEdit(self)
        self.textbox.setGeometry(25, 20, 350, 280)
        self.textbox.setReadOnly(True)

        # Path overview
        self.scan_path = QLineEdit(self)
        self.scan_path.setGeometry(70, 365, 250, 20)
        self.scan_path.setReadOnly(True)

        # Path status
        self.status = QtWidgets.QLabel(self)
        self.status.setText('❌')
        self.status.move(43, 358)

        # Clear scan and path button
        self.clear_button = QtWidgets.QPushButton(self)
        self.clear_button.setText('Clear Scans')
        self.clear_button.setGeometry(210, 400, 100, 30)
        self.clear_button.clicked.connect(self.clear)

        # Scan start button
        self.scanner = QtWidgets.QPushButton(self)
        self.scanner.setText('Scan')
        self.scanner.setGeometry(80, 400, 100, 30)
        self.scanner.clicked.connect(self.scan)

        # API key add button
        self.add_key = QtWidgets.QPushButton(self)
        self.add_key.setText('Add API Key')
        self.add_key.setGeometry(140, 447, 100, 30)
        self.add_key.clicked.connect(self.add_api_key)

        # Hash operation checkbox
        self.hash_status = QCheckBox(self)
        self.hash_status.setText('Manual Hashing')
        self.hash_status.move(50, 482)
        self.hash_status.setChecked(True)

        # .txt output checkbox
        self.file_output = QCheckBox(self)
        self.file_output.setText('.txt Output')
        self.file_output.move(160, 482)

        # Show undetected checkbox
        self.show_undetected = QCheckBox(self)
        self.show_undetected.setText('View Undetected')
        self.show_undetected.setGeometry(250, 482, 105, 30)  # Increase size so text could fit

    def clear(self) -> None:
        """Clears the scan textbox and the file path and resets the path status"""
        self.textbox.clear()
        self.scan_path.clear()
        self.status.setText('❌')

    def get_path(self, isfile: bool) -> None:
        """Adds path to scan if the path is a file/folder"""
        if isfile:
            path = QFileDialog.getOpenFileName(self,
                                               'Select File',
                                               os.path.dirname(os.path.abspath(__file__)))
            if path[0]:
                self.scan_path.setText(os.path.abspath(path[0]))
                self.status.setText('✔')
        else:
            path = QFileDialog.getExistingDirectory(self,
                                                    'Select Directory',
                                                    os.path.dirname(os.path.abspath(__file__)))
            if path:
                self.scan_path.setText(os.path.abspath(path))
                self.status.setText('✔')

    async def append_report(self, path: str) -> None:
        """Outputs a scan to the textbox"""
        if os.path.isfile(path):
            self.textbox.appendPlainText('-' * 64)
            self.textbox.appendHtml('File scan started at: <span style="color: blue;">' +
                                    f'{datetime.now().strftime("%H:%M:%S, %d/%m/%Y")}</span>' +
                                    f'<br>Selected File: <span style="color: blue;">{path}</span>' +
                                    '<br>Scanning...<br>')
            async with aiohttp.ClientSession() as session:
                report = await filereport.get_file_report(path, self.api_key, session,
                                                          manual=self.hash_status.isChecked(),
                                                          show_undetected=self.show_undetected.isChecked())
            if report:
                self.textbox.appendHtml(report + '<br>')
            self.textbox.appendHtml('File scan ended at: <span style="color: blue;">'
                                    f'{datetime.now().strftime("%H:%M:%S, %d/%m/%Y")}</span>')
            self.textbox.appendPlainText('-' * 64)
            if self.file_output.isChecked():
                self.txt_output_to_file()

        if os.path.isdir(path):
            self.textbox.appendPlainText('-' * 64)
            self.textbox.appendHtml('File scan started at: <span style="color: blue;">' +
                                    f'{datetime.now().strftime("%H:%M:%S, %d/%m/%Y")}</span>' +
                                    f'<br>Selected Folder: <span style="color: blue;">{path}</span>' +
                                    '<br>Scanning...<br>')
            async for report in filereport.scan(path, self.api_key, self.show_undetected.isChecked(),
                                                manual=self.hash_status.isChecked()):
                if report:
                    self.textbox.appendHtml(report + '<br>')
            self.textbox.appendHtml('File scan ended at: <span style="color: blue;">'
                                    f'{datetime.now().strftime("%H:%M:%S, %d/%m/%Y")}</span>')
            self.textbox.appendPlainText('-' * 64)
            if self.file_output.isChecked():
                self.txt_output_to_file()

    def scan(self) -> None:
        """Starts the scanning process if an API key and a path are inserted"""
        path = self.scan_path.text()
        if path and self.api_key:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(self.append_report(path))
        else:
            # Create a message box if an API key or a path is missing`
            msg = QtWidgets.QMessageBox()
            msg.setIcon(QtWidgets.QMessageBox.Information)
            msg.setText('Please enter an API key and a file/folder path!')
            msg.setWindowTitle('Missing key or path')
            msg.setWindowIcon(QIcon('imgs/icon.png'))
            msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
            msg.exec_()

    def add_api_key(self) -> None:
        """Adds an API key for the program from input"""
        key, ok = QInputDialog.getText(self,
                                       'Enter Virus Total API Key',
                                       'Enter Virus Total API Key',
                                       QLineEdit.Normal,
                                       self.api_key)
        if ok and key:  # If the user clicked OK and entered a key
            self.api_key = key

    def txt_output_to_file(self) -> None:
        """Outputs the last scan on screen to .txt file"""
        scans = self.textbox.toPlainText()
        last_scan = scans.split('-' * 64)[-2].split('-' * 64)[-1][1:]  # Find last scan using split and remove line feed
        # Fetch name by date and modify string
        filename = 'Scan ' + findall('..:..:.., ../../.{4}', last_scan)[0].replace(':', '-').replace('/', '-') + '.txt'
        with open(filename, 'w') as f:
            f.write(last_scan)


def window() -> None:
    app = QApplication(sys.argv)
    with open('style.css', 'r') as f:
        style = f.read()
    app.setStyleSheet(style)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    window()
