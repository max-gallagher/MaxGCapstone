import sys
import json
import random
import string
import datetime
import base64
import os
import boto3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, \
    QMessageBox, QFormLayout, QListWidget, QListWidgetItem, QInputDialog, QSizePolicy  # Import required PyQt5 modules
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

# Initialize Boto3 client for Amazon S3
s3 = boto3.client('s3')

# Example style sheet for the Password Manager UI
stylesheet = """
QWidget {
    background-color: #f0f0f0;
    color: #333333;
    font-family: Arial, sans-serif;
}

QLineEdit {
    border: 1px solid #cccccc;
    border-radius: 5px;
    padding: 5px;
}

QPushButton {
    background-color: #007bff;
    color: #ffffff;
    border: none;
    border-radius: 5px;
    padding: 8px 16px;
}

QPushButton:hover {
    background-color: #0056b3;
}

QLabel {
    font-weight: bold;
}

QListWidget {
    border: 1px solid #cccccc;
    border-radius: 5px;
    padding: 5px;
    background-color: #ffffff;
}

QListWidget::item {
    padding: 5px;
}

QListWidget::item:selected {
    background-color: #007bff;
    color: #ffffff;
}

"""

class PasswordManager(QMainWindow):
    # Main window for the Password Manager application.

    def __init__(self):
        # Initialize the PasswordManager
        super().__init__()

        # Set window title and initial size
        self.setWindowTitle("Password Manager")

        # Initialize the login widget
        self.login_widget = LoginWidget(self)
        self.setCentralWidget(self.login_widget)
        self.setGeometry(100, 100, 850, 400)  

class LoginWidget(QWidget):
    # Widget for the login page of the Password Manager.

    def __init__(self, parent):
        # Initialize the LoginWidget.
        super().__init__()
        self.parent = parent  # Reference to the parent window

        layout = QVBoxLayout()  # Vertical layout for the login page

        # Title Banner
        title_banner = QLabel("Max's Password Manager")
        title_banner.setAlignment(Qt.AlignCenter)
        title_banner.setFont(QFont("Tahoma", 24, QFont.Bold))  # Set font to Tahoma
        layout.addWidget(title_banner)

        # Username and Password Fields
        self.username_label = QLabel("Username:")
        self.username_label.setFont(QFont("Arial", 14, QFont.Bold))  # Increase font size and set bold
        self.username_entry = QLineEdit()
        self.username_entry.setFont(QFont("Arial", 12))  # Set font size for username entry
        self.password_label = QLabel("Password:")
        self.password_label.setFont(QFont("Arial", 14, QFont.Bold))  # Increase font size and set bold
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.password_entry.setFont(QFont("Arial", 12))  # Set font size for password entry

        # Login and Create User Buttons
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)

        self.create_user_button = QPushButton("Create New User")
        self.create_user_button.clicked.connect(self.create_new_user)

        # Add widgets to the layout
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_entry)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.login_button)
        layout.addWidget(self.create_user_button)

        self.setLayout(layout)  # Set the layout for the widget

    def login(self):
        # Handle login functionality.
        username = self.username_entry.text()
        password = self.password_entry.text()

        if user_exists(username, password):
            # Prompt for master password if user exists
            master_password, ok = QInputDialog.getText(self, 'Master Password', 'Enter your master password:')
            if ok:
                # Switch to PasswordManagerWidget if master password is entered correctly
                self.parent.setCentralWidget(PasswordManagerWidget(self.parent, username, master_password))
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password. Please try again.")

    def create_new_user(self):
        # Handle creating a new user.
        username, ok = QInputDialog.getText(self, 'Create New User', 'Enter new username:')
        if ok:
            password, ok = QInputDialog.getText(self, 'Create New User', 'Enter password:')
            if ok:
                try:
                    # Load existing users from S3
                    obj = s3.get_object(Bucket='mgcapstonepasswordmanager', Key="users.json")
                    users = json.loads(obj['Body'].read().decode('utf-8'))
                except Exception as e:
                    print(f"Error loading users: {e}")
                    users = {}

                # Add new user to the dictionary
                users[username] = password

                try:
                    # Save updated user dictionary to S3
                    s3.put_object(Bucket='mgcapstonepasswordmanager', Key="users.json", Body=json.dumps(users))
                    QMessageBox.information(self, "New User Created", "New user created successfully.")
                except Exception as e:
                    print(f"Error creating new user: {e}")


class PasswordManagerWidget(QWidget):
    # Widget for managing passwords.

    def __init__(self, parent, username, master_password):
        # Initialize the PasswordManagerWidget.
        super().__init__()

        self.parent = parent
        self.username = username
        self.passwords = []
        self.password_key = self._derive_key(master_password)

        self.setGeometry(100, 100, 850, 1000)  # Initial size of the window
        
        self.load_passwords()  # Load passwords from S3

        layout = QVBoxLayout()  # Vertical layout for the widget

        # Form layout for password input fields
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
        self.delete_password_button = QPushButton("Delete")  # Button to delete password
        self.delete_password_button.clicked.connect(self.delete_password)  # Connect delete button to delete_password method
        self.result_label = QLabel()

        # Add widgets to the form layout
        form_layout.addRow("Website:", self.website_entry)
        form_layout.addRow("Username:", self.username_entry)
        form_layout.addRow("Password Length:", self.length_entry)
        form_layout.addRow("Password Generated:", self.password_entry)
        form_layout.addRow(self.generate_button)
        form_layout.addRow(self.save_button)
        form_layout.addRow(self.delete_password_button) 
        form_layout.addRow(self.result_label)

        layout.addLayout(form_layout)  # Add form layout to the main layout

        # List widget to display passwords
        self.password_list = QListWidget()
        self.password_list.itemClicked.connect(self.copy_password_to_clipboard)  # Connect itemClicked signal to copy_password_to_clipboard method
        layout.addWidget(self.password_list)

        # Button to show/hide passwords
        self.show_password_button = QPushButton("Show/Hide Passwords")
        self.show_password_button.clicked.connect(self.show_passwords)
        layout.addWidget(self.show_password_button)

        # Buttons for sorting passwords
        self.sort_by_website_button = QPushButton("Sort by Website")
        self.sort_by_website_button.clicked.connect(self.sort_by_website)
        self.sort_by_username_button = QPushButton("Sort by Username")
        self.sort_by_username_button.clicked.connect(self.sort_by_username)
        self.sort_by_datetime_button = QPushButton("Sort by Date/Time")  # Button to sort by date/time
        self.sort_by_datetime_button.clicked.connect(self.sort_by_datetime)  # Connect button to sort_by_datetime method

        # Add sort buttons to layout
        layout.addWidget(self.sort_by_website_button)
        layout.addWidget(self.sort_by_username_button)
        layout.addWidget(self.sort_by_datetime_button)

        self.setLayout(layout)  # Set the layout for the widget

        self.update_password_list()  # Update password list widget with current passwords

    def generate_password(self):
        # Generate a random password.
        try:
            length = int(self.length_entry.text())
            characters = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choice(characters) for _ in range(length))
            self.password_entry.setText(password)
        except ValueError:
            QMessageBox.warning(self, "Invalid Length", "Please enter a valid password length.")

    def save_password(self):
        # Save a password entry.
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
        # Show or hide passwords.
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
        # Clear password input fields.
        self.website_entry.clear()
        self.username_entry.clear()
        self.password_entry.clear()
        self.length_entry.clear()

    def update_password_list(self):
        # Update the password list widget.
        self.password_list.clear()
        for entry in self.passwords:
            item = QListWidgetItem()
            item_text = f"Website: {entry['website']} | Username: {entry['username']}"
            if 'timestamp' in entry:
                item_text += f" | Date Generated: {entry['timestamp']}"
            item.setText(item_text)
            self.password_list.addItem(item)

    def load_passwords(self):
        # Load passwords from S3.
        try:
            obj = s3.get_object(Bucket='mgcapstonepasswordmanager', Key=f"{self.username}_passwords.json")
            encrypted_passwords = json.loads(obj['Body'].read().decode('utf-8'))

            for entry in encrypted_passwords:
                decrypted_entry = {
                    "website": self._decrypt(entry['website'], self.password_key),
                    "username": self._decrypt(entry['username'], self.password_key),
                    "password": self._decrypt(entry['password'], self.password_key),
                    "timestamp": entry['timestamp']
                }
                self.passwords.append(decrypted_entry)

        except Exception as e:
            print(f"Error loading passwords: {e}")
            self.passwords = []

    def save_passwords(self):
        # Save passwords to S3.
        encrypted_passwords = []
        for entry in self.passwords:
            encrypted_entry = {
                "website": self._encrypt(entry['website'], self.password_key),
                "username": self._encrypt(entry['username'], self.password_key),
                "password": self._encrypt(entry['password'], self.password_key),
                "timestamp": entry['timestamp']
            }
            encrypted_passwords.append(encrypted_entry)

        try:
            s3.put_object(Bucket='mgcapstonepasswordmanager', Key=f"{self.username}_passwords.json", Body=json.dumps(encrypted_passwords))
        except Exception as e:
            print(f"Error saving passwords: {e}")

    def _derive_key(self, password):
        # Derive encryption key from master password.
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
        # Encrypt plaintext using AES-GCM.
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return base64.urlsafe_b64encode(nonce + encryptor.tag + ciphertext).decode()

    def _decrypt(self, ciphertext, key):
        # Decrypt ciphertext using AES-GCM.
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
        except Exception as e:
            print(f"Error decrypting: {e}")
            return ""

    def sort_by_website(self):
        # Sort passwords by website. 
        self.password_list.clear()
        sorted_passwords = sorted(self.passwords, key=lambda x: x['website'])
        self.passwords = sorted_passwords
        self.update_password_list()

    def sort_by_username(self):
        # Sort passwords by username.
        self.password_list.clear()
        sorted_passwords = sorted(self.passwords, key=lambda x: x['username'])
        self.passwords = sorted_passwords
        self.update_password_list()

    def sort_by_datetime(self):
        # Sort passwords by date/time.
        self.password_list.clear()
        sorted_passwords = sorted(self.passwords, key=lambda x: datetime.datetime.strptime(x['timestamp'], "%Y-%m-%d %H:%M:%S"), reverse=True)
        self.passwords = sorted_passwords
        self.update_password_list()

    def delete_password(self):
        # Delete selected password.
        selected_items = self.password_list.selectedItems()
        if selected_items:
            selected_item = selected_items[0]
            index = self.password_list.row(selected_item)
            del self.passwords[index]
            self.save_passwords()
            self.update_password_list()
            QMessageBox.information(self, "Password Deleted", "Password deleted successfully.")
        else:
            QMessageBox.warning(self, "No Password Selected", "Please select a password to delete.")

    def copy_password_to_clipboard(self, item):
        # Copy password to clipboard.
        password = item.text().split("Password: ")[-1]
        clipboard = QApplication.clipboard()
        clipboard.setText(password)


def user_exists(username, password):
    # Check if user exists.
    try:
        obj = s3.get_object(Bucket='mgcapstonepasswordmanager', Key="users.json")
        users = json.loads(obj['Body'].read().decode('utf-8'))
        return users.get(username) == password
    except Exception as e:
        print(f"Error checking user: {e}")
        return False


def main():
    # Main function to run the application.
    app = QApplication(sys.argv)
    try:
        window = PasswordManager()
        window.setStyleSheet(stylesheet)  # Apply the style sheet here
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Error initializing application: {e}")


if __name__ == "__main__":
    main()
