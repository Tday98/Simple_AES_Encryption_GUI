import sys

from PyQt6.QtWidgets import (QApplication, QWidget, QPushButton, QMainWindow,
                             QDialog,
                             QVBoxLayout, QMessageBox, QFileDialog, QPlainTextEdit,
                             QHBoxLayout)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = iv = None
with open("key.txt", "rb") as file:
    key = file.readline().strip()
    iv = file.readline().strip()
    print(key, iv)


def encrypt(plaintext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    pad = padding.PKCS7(algorithms.AES.block_size).padder()
    pad_plaintext = pad.update(plaintext) + pad.finalize()

    ct = encryptor.update(pad_plaintext) + encryptor.finalize()

    return ct


def decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    unpad = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpad.update(padded_plain) + unpad.finalize()

    return plaintext


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('File Management System')
        self.setMinimumSize(800, 700)

        self.widget = QWidget()
        self.setCentralWidget(self.widget)

        self.modify = QPushButton('Modify')
        self.read = QPushButton('Read')

        self.modify.clicked.connect(self.modify_open)
        self.read.clicked.connect(self.read_open)

        layout = QHBoxLayout()
        layout.addWidget(self.modify)
        layout.addWidget(self.read)
        self.widget.setLayout(layout)

    def modify_open(self):
        dialog = ModifyDialog()
        dialog.exec()

    def read_open(self):
        dialog = ReadDialog()
        dialog.exec()


class ModifyDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setMinimumSize(500, 400)
        self.setWindowTitle('Modify File')

        self.file_path = ''
        # Open file dialog
        self.open_file_dialog()

    def open_file_dialog(self):
        fname, x = QFileDialog.getOpenFileName(self, 'Open File', '', 'All Files (*)')
        print(fname)
        if fname:
            try:
                with open(fname, 'rb') as file:
                    text = file.read()
                decrypted = decrypt(text, key, iv)
                self.file_path = fname

                # Display file content
                self.fileText = QPlainTextEdit()
                self.fileText.setPlainText(decrypted.decode('utf-8'))

                # Save button
                save_button = QPushButton("Save")
                save_button.clicked.connect(self.save_file)

                layout = QVBoxLayout()
                layout.addWidget(self.fileText)
                layout.addWidget(save_button)
                self.setLayout(layout)
            except Exception:
                QMessageBox.critical(self, "Error", "Could not open file")

    def save_file(self):
        if self.file_path:
            try:
                with open(self.file_path, 'wb') as file:
                    encrypted_fileText = encrypt(self.fileText.toPlainText().encode('utf-8'), key, iv)
                    file.write(encrypted_fileText)
                QMessageBox.information(self, "Success", "File saved successfully!")
            except Exception:
                QMessageBox.critical(self, "Error", "Could not open file")
            self.close()


class ReadDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setMinimumSize(500, 400)
        self.setWindowTitle('Read File')

        self.file_path = ''
        # Open file dialog
        self.open_file_dialog()

    def open_file_dialog(self):
        fname, x = QFileDialog.getOpenFileName(self, 'Open File', '', 'All Files (*)')
        if fname:
            try:
                with open(fname, 'rb') as file:
                    text = file.read()
                decrypted_text = decrypt(text, key, iv)
                self.file_path = fname

                # Display file content
                self.fileText = QPlainTextEdit()
                self.fileText.setPlainText(decrypted_text.decode('utf-8'))
                self.fileText.setReadOnly(True)

                # Save button
                save_button = QPushButton("Exit")
                save_button.clicked.connect(self.exit_file)

                layout = QVBoxLayout()
                layout.addWidget(self.fileText)
                layout.addWidget(save_button)
                self.setLayout(layout)
            except Exception:
                QMessageBox.critical(self, "Error", "Could not open file")

    def exit_file(self):
        if self.file_path:
            try:
                with open(self.file_path, 'wb') as file:
                    encrypted_fileText = encrypt(self.fileText.toPlainText().encode('utf-8'), key, iv)
                    file.write(encrypted_fileText)
                QMessageBox.information(self, "Success", "Exited successfully!")
            except Exception:
                QMessageBox.critical(self, "Error", "Could not open file")
            self.close()


app = QApplication(sys.argv)
window = MainWindow()
window.show()
sys.exit(app.exec())
