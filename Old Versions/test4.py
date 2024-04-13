import sys
import os
import json
import random
import string
import datetime
import base64
import re
import cryptography
import binascii 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, \
    QTextEdit, QListWidget, QMessageBox, QFormLayout, QListWidgetItem, QInputDialog
from PyQt5.QtCore import Qt  # Add this line to import Qt


class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 600, 400)

        self.login_widget = LoginWidget(self)
        self.setCentralWidget(self.login_widget)


# Widget for user login
class LoginWidget(QWidget):
    def __init__(self, parent):
        super().__init__()

        self.parent = parent

        layout = QVBoxLayout()

        self.username_label = QLabel("Username:")
        self.username_entry = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)

        # Adjusted vertical and horizontal spacing for better alignment
        layout.addWidget(self.username_label, alignment=Qt.Alignment())
        layout.addWidget(self.username_entry, alignment=Qt.Alignment())
        layout.addWidget(self.password_label, alignment=Qt.Alignment())
        layout.addWidget(self.password_entry, alignment=Qt.Alignment())
        layout.addWidget(self.login_button, alignment=Qt.Alignment())

        # Added some additional spacing for a cleaner look
        layout.addSpacing(20)

        self.setLayout(layout)

    def login(self):
        username = self.username_entry.text()
        password = self.password_entry.text()

        # Check if the provided username and password exist in the user database
        if user_exists(username, password):
            master_password, ok = QInputDialog.getText(self, 'Master Password', 'Enter your master password:')
            if ok:
                # If login is successful, switch to the password manager widget
                self.parent.setCentralWidget(PasswordManagerWidget(self.parent, username, master_password))
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password. Please try again.")


class PasswordManagerWidget(QWidget):
    def __init__(self, parent, username, master_password):
        super().__init__()

        self.parent = parent
        self.username = username
        self.passwords = []
        self.password_key = self._derive_key(master_password)

        self.load_passwords()

        layout = QVBoxLayout()

        form_layout = QFormLayout()
        self.website_entry = QLineEdit()
        self.username_entry = QLineEdit()
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.length_entry = QLineEdit()
        self.generate_button = QPushButton("Generate Password")
        self.generate_button.clicked.connect(self.generate_password)
        self.save_button = QPushButton("Save Password")
        self.save_button.clicked.connect(self.save_password)
        self.result_label = QLabel()

        form_layout.addRow("Website:", self.website_entry)
        form_layout.addRow("Username:", self.username_entry)
        form_layout.addRow("Password Length:", self.length_entry)
        form_layout.addRow("Password Generated:", self.password_entry)
        form_layout.addRow(self.generate_button)
        form_layout.addRow(self.save_button)
        form_layout.addRow(self.result_label)

        layout.addLayout(form_layout)

        self.password_list = QListWidget()
        layout.addWidget(self.password_list)

        self.show_password_button = QPushButton("Show/Hide Passwords")
        self.show_password_button.clicked.connect(self.show_passwords)
        layout.addWidget(self.show_password_button)

        self.setLayout(layout)

        self.update_password_list()

    def generate_password(self):
        try:
            length = int(self.length_entry.text())
            characters = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choice(characters) for _ in range(length))
            self.password_entry.setText(password)
        except ValueError:
            QMessageBox.warning(self, "Invalid Length", "Please enter a valid password length.")

    def save_password(self):
        website = self.website_entry.text()
        username = self.username_entry.text()
        password = self.password_entry.text()

        current_datetime = datetime.datetime.now()

        if not website or not username or not password:
            QMessageBox.warning(self, "Error", "Please enter website, username, and password.")
            return

        entry = {
            "website": website,
            "username": username,
            "password": password,
            "timestamp": current_datetime.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.passwords.append(entry)
        self.save_passwords()
        self.update_password_list()
        self.clear_entries()
        self.result_label.setText("Password saved successfully!")

    def show_passwords(self):
        for index in range(self.password_list.count()):
            item = self.password_list.item(index)
            password_item = self.passwords[index]
            item_text = (
                f"Website: {password_item['website']} | "
                f"Username: {password_item['username']} | "
                f"Date Generated: {password_item['timestamp']} | "
                f"Password: {password_item['password']}"
            )
            item.setText(item_text if not password_item.get("show_password", False) else f"Website: {password_item['website']} | Username: {password_item['username']}")

            password_item["show_password"] = not password_item.get("show_password", False)

    def clear_entries(self):
        self.website_entry.clear()
        self.username_entry.clear()
        self.password_entry.clear()
        self.length_entry.clear()

    def update_password_list(self):
        self.password_list.clear()
        for entry in self.passwords:
            item = QListWidgetItem()
            item_text = f"Website: {entry['website']} | Username: {entry['username']}"
            if 'timestamp' in entry:
                item_text += f" | Date Generated: {entry['timestamp']}"
            item.setText(item_text)
            self.password_list.addItem(item)

    def load_passwords(self):
        try:
            with open(f"{self.username}_passwords.json", "r") as file:
                encrypted_passwords = json.load(file)

            for entry in encrypted_passwords:
                decrypted_entry = {
                    "website": self._decrypt(entry['website'], self.password_key),
                    "username": self._decrypt(entry['username'], self.password_key),
                    "password": self._decrypt(entry['password'], self.password_key),
                    "timestamp": entry['timestamp']
                }
                self.passwords.append(decrypted_entry)

        except FileNotFoundError:
            self.passwords = []
        except json.decoder.JSONDecodeError:
            print("JSON file is empty or not in a valid format.")

    def save_passwords(self):
        encrypted_passwords = []
        for entry in self.passwords:
            encrypted_entry = {
                "website": self._encrypt(entry['website'], self.password_key),
                "username": self._encrypt(entry['username'], self.password_key),
                "password": self._encrypt(entry['password'], self.password_key),
                "timestamp": entry['timestamp']
            }
            encrypted_passwords.append(encrypted_entry)

        with open(f"{self.username}_passwords.json", "w") as file:
            json.dump(encrypted_passwords, file)

    def _derive_key(self, password):
        salt = b'some_random_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=salt,
            length=32,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key

    def _encrypt(self, plaintext, key):
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return base64.urlsafe_b64encode(nonce + encryptor.tag + ciphertext).decode()

    def _decrypt(self, ciphertext, key):
        try:
            data = base64.urlsafe_b64decode(ciphertext)
            nonce = data[:16]
            tag = data[16:32]

            if len(tag) < 16:
                raise ValueError("Authentication tag must be 16 bytes or longer.")

            cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(data[32:])
            plaintext += decryptor.finalize()
            return plaintext.decode()
        except binascii.Error as e:
            print(f"Error decoding base64: {e}")
            return ""
        except cryptography.exceptions.InvalidTag:
            print("Authentication tag verification failed. The provided tag is incorrect.")
            return ""
        except ValueError as ve:
            print(f"ValueError: {ve}")
            return ""


def user_exists(username, password):
    users = {"testuser": "test123", "max": "password123"}
    return users.get(username) == password


def main():
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
