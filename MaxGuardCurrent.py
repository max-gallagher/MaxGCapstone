import sys
import json
import random
import string
import datetime
import base64
import os
import boto3
# Import modules for MFA
import smtplib
from email.mime.text import MIMEText
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
# Import GUI modules
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, \
    QMessageBox, QFormLayout, QListWidget, QListWidgetItem, QInputDialog, QSizePolicy, QCheckBox, QAction, QMenu
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QTimer
# Import cryptography modules for password encryption/decryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet

# Initialize Boto3 client for Amazon S3
s3 = boto3.client(
    's3',
    aws_access_key_id='AKIATQOYUXLO62SPAN6Q',
    aws_secret_access_key='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',
)

# Gmail SMTP Configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 465  # SSL port
EMAIL_SENDER = 'maxguardmfa@gmail.com'  # Your Gmail address
EMAIL_SENDER_PASSWORD = 'hqho cmoz vwzw qctv'  # Your Gmail password

# Define default and high contrast/dark mode stylesheets
default_stylesheet = """
QWidget {
    background-color: #FAF9F6;
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


dark_stylesheet = """
QWidget {
    background-color: #282828;
    color: #f0f0f0;
    font-family: Arial, sans-serif;
}

QLineEdit {
    border: 1px solid #555555;
    border-radius: 5px;
    padding: 5px;
    background-color: #3a3a3a;
    color: #ffffff;
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
    color: #f0f0f0;
}

QListWidget {
    border: 1px solid #555555;
    border-radius: 5px;
    padding: 5px;
    background-color: #3a3a3a;
    color: #ffffff;
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

        # Add button for toggling high contrast/dark mode
        self.create_button()

    def create_button(self):
        # Create a button for toggling high contrast/dark mode
        self.toggle_mode_button = QPushButton('Contrast Mode', self)
        self.toggle_mode_button.setCheckable(True)
        self.toggle_mode_button.setChecked(False)  # Default to unchecked
        self.toggle_mode_button.clicked.connect(self.toggle_mode)
        self.toggle_mode_button.setGeometry(10, 10, 120, 30)
        self.toggle_mode_button.setStyleSheet("QPushButton { background-color: #083e78; color: #ffffff; border: 1px solid #007bff; border-radius: 10px; }"
                                              "QPushButton:checked { background-color: #6c757d; border-color: #6c757d; }")

    def toggle_mode(self):
        # Toggle between default and high contrast/dark mode
        if self.toggle_mode_button.isChecked():
            # Apply dark mode stylesheet
            self.setStyleSheet(default_stylesheet)
        else:
            # Apply default stylesheet
            self.setStyleSheet(dark_stylesheet)

class LoginWidget(QWidget):
    # Widget for the login page of the Password Manager.

    def __init__(self, parent):
        # Initialize the LoginWidget.
        super().__init__()
        self.parent = parent  # Reference to the parent window

        layout = QVBoxLayout()  # Vertical layout for the login page

        # Title Banner
        title_banner = QLabel("MaxGuard Password Manager")
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
            # Generate verification code and send email
            verification_code = generate_verification_code()
            send_verification_email(username, verification_code)
            # Prompt for verification code
            entered_code, ok = QInputDialog.getText(self, 'Verification Code', 'Enter the verification code sent to your email:')
            if ok and verify_code(entered_code, verification_code):
                # Switch to PasswordManagerWidget if verification successful
                self.parent.setCentralWidget(PasswordManagerWidget(self.parent, username, password))  # Pass master_password here
            else:
                QMessageBox.warning(self, "Verification Failed", "Invalid verification code. Please try again.")
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password. Please try again.")

    def create_new_user(self):
        # Handle creating a new user.
        username, ok = QInputDialog.getText(self, 'Create New User', 'Enter username (email):')
        if ok:
            # Check if username already exists
            try:
                obj = s3.get_object(Bucket='mgcapstonepasswordmanager', Key="users.json")
                existing_users = json.loads(obj['Body'].read().decode('utf-8'))
            except Exception as e:
                print(f"Error loading existing users: {e}")
                existing_users = {}

            if username in existing_users:
                QMessageBox.warning(self, "Username Exists", "Username already exists. Please choose a different username.")
                return

            # Prompt for password
            password, ok = QInputDialog.getText(self, 'Create New User', 'Enter password (must contain at least one uppercase letter, one lowercase letter, one digit, and one special character):')
            if ok:
                # Validate password strength
                if not self.is_secure_password(password):
                    QMessageBox.warning(self, "Weak Password", "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
                    return

                try:
                    # Add new user to the dictionary
                    existing_users[username] = password

                    # Save updated user dictionary to S3
                    s3.put_object(Bucket='mgcapstonepasswordmanager', Key="users.json", Body=json.dumps(existing_users))
                    QMessageBox.information(self, "New User Created", "New user created successfully.")
                except Exception as e:
                    print(f"Error creating new user: {e}")

    def is_secure_password(self, password):
        # Validate password strength (at least one uppercase, one lowercase, one digit, and one special character)
        if not any(char.isupper() for char in password):
            return False
        if not any(char.islower() for char in password):
            return False
        if not any(char.isdigit() for char in password):
            return False
        if not any(char in string.punctuation for char in password):
            return False
        return True

class PasswordManagerWidget(QWidget):
    # Widget for managing passwords.

    def __init__(self, parent, username, master_password):
        # Initialize the PasswordManagerWidget.
        super().__init__()

        self.setMinimumSize(850, 600)  # Set a minimum size hint

        self.parent = parent
        self.username = username
        self.passwords = []
        self.password_key = self._derive_key(master_password)

        self.setGeometry(100, 100, 850, 1000)  # Initial size of the window

        self.load_passwords()  # Load passwords from S3

        layout = QVBoxLayout()  # Vertical layout for the widget

        # Add the contrast mode button
        layout.addWidget(self.parent.toggle_mode_button)

        # Form layout for password input fields
        form_layout = QFormLayout()
        self.website_entry = QLineEdit()
        self.username_entry = QLineEdit()
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.length_entry = QLineEdit()
        self.custom_password_entry = QLineEdit()  # Add custom password entry field
        self.generate_save_button = QPushButton("Generate and Save Password")  
        self.generate_save_button.clicked.connect(self.generate_and_save_password) 
        self.delete_password_button = QPushButton("Delete")  # Button to delete password
        self.delete_password_button.clicked.connect(self.delete_password)  # Connect delete button to delete_password method
        self.result_label = QLabel()

        # Add widgets to the form layout
        form_layout.addRow("Website:", self.website_entry)
        form_layout.addRow("Username:", self.username_entry)
        form_layout.addRow("Password Length:", self.length_entry)
        form_layout.addRow("Custom Password:", self.custom_password_entry)  # Add custom password entry field
        form_layout.addRow(self.generate_save_button)  
        form_layout.addRow(self.delete_password_button)
        form_layout.addRow(self.result_label)

        layout.addLayout(form_layout)  # Add form layout to the main layout

        # Add search input field
        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Search Passwords")
        self.search_entry.textChanged.connect(self.search_passwords)
        layout.addWidget(self.search_entry)

        # List widget to display passwords
        self.password_list = QListWidget()
        self.password_list.itemClicked.connect(self.copy_password_to_clipboard)  # Connect itemClicked signal to copy_password_to_clipboard method
        layout.addWidget(self.password_list)

        # Button to show/hide passwords
        self.show_password_button = QPushButton("Show/Hide Passwords")
        self.show_password_button.clicked.connect(self.toggle_show_passwords)  # Correct the connection
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

    def generate_and_save_password(self):
        # Generate and save a password entry.
        website = self.website_entry.text()
        username = self.username_entry.text()
        custom_password = self.custom_password_entry.text()  # Get the custom password
        password_length_text = self.length_entry.text()  # Get the password length

        current_datetime = datetime.datetime.now()

        if not website or not username:
            QMessageBox.warning(self, "Error", "Please enter website and username.")
            return

        if custom_password and not self.is_secure_password(custom_password):
            QMessageBox.warning(self, "Weak Password", "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
            return

        if not custom_password and not password_length_text:
            QMessageBox.warning(self, "Missing Fields", "Please enter either a custom password or a password length.")
            return

        if custom_password:  # Use custom password if provided
            password = custom_password
        else:
            try:
                password_length = int(password_length_text)
                if password_length < 8:
                    QMessageBox.warning(self, "Weak Password", "Password length must be at least 8 characters.")
                    return
                password = self.generate_password(password_length)  # Corrected method call
            except ValueError:
                QMessageBox.warning(self, "Invalid Length", "Please enter a valid password length.")
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

    def generate_password(self, length):
        # Generate a random password.
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

    def is_secure_password(self, password):
        # Validate password strength (at least one uppercase, one lowercase, one digit, and one special character)
        if not any(char.isupper() for char in password):
            return False
        if not any(char.islower() for char in password):
            return False
        if not any(char.isdigit() for char in password):
            return False
        if not any(char in string.punctuation for char in password):
            return False
        return True

    def clear_entries(self):
        # Clear password input fields.
        self.website_entry.clear()
        self.username_entry.clear()
        self.password_entry.clear()
        self.length_entry.clear()
        self.custom_password_entry.clear()

    def search_passwords(self, query):
        # Filter passwords based on search query
        if query:
            filtered_passwords = [entry for entry in self.passwords if query.lower() in entry['website'].lower() or query.lower() in entry['username'].lower()]
            self.update_password_list(filtered_passwords)  # Update password list with filtered passwords
        else:
            self.update_password_list()  # If search query is empty, show all passwords

    def update_password_list(self, passwords=None):
        # Update the password list widget.
        self.password_list.clear()
        passwords = passwords or self.passwords  # If passwords are not provided, use self.passwords
        for entry in passwords:
            item = QListWidgetItem()
            password = entry['password']
            masked_password = password[0] + '*' * (len(password) - 2) + password[-1] if len(password) > 2 else '*' * len(password)
            item_text = f"Website: {entry['website']} | Username: {entry['username']} | Date Generated: {entry['timestamp']} | Password: {masked_password}"
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

    def save_passwords(self):
        # Save passwords to S3.
        try:
            encrypted_passwords = []
            for entry in self.passwords:
                encrypted_entry = {
                    "website": self._encrypt(entry['website'], self.password_key),
                    "username": self._encrypt(entry['username'], self.password_key),
                    "password": self._encrypt(entry['password'], self.password_key),
                    "timestamp": entry['timestamp']
                }
                encrypted_passwords.append(encrypted_entry)

            s3.put_object(Bucket='mgcapstonepasswordmanager', Key=f"{self.username}_passwords.json", Body=json.dumps(encrypted_passwords))
        except Exception as e:
            print(f"Error saving passwords: {e}")

    def delete_password(self):
        # Delete selected password entry.
        selected_items = self.password_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a password to delete.")
            return

        item = selected_items[0]
        index = self.password_list.row(item)
        del self.passwords[index]
        self.save_passwords()
        self.update_password_list()

    def copy_password_to_clipboard(self, item):
        # Copy password to clipboard.
        password = item.text().split("Password: ")[1]
        clipboard = QApplication.clipboard()
        clipboard.setText(password)
        QMessageBox.information(self, "Password Copied", "Password copied to clipboard.")

        # Clear clipboard after a certain period of time
        QTimer.singleShot(15000, self.clear_clipboard)

    def clear_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.clear()
        QMessageBox.information(self, "Clipboard Cleared", "Clipboard cleared.")

    def toggle_show_passwords(self):
        # Show or hide passwords.
        for index in range(self.password_list.count()):
            item = self.password_list.item(index)
            password_item = self.passwords[index]

            # Retrieve original text if available
            original_text = item.data(Qt.UserRole)

            if not password_item.get("show_password", False):
                # Show password
                password = password_item['password']
                # Store original text to restore later
                item.setData(Qt.UserRole, item.text())
                item.setText(f"Website: {password_item['website']} | Username: {password_item['username']} | Date Generated: {password_item['timestamp']} | Password: {password}")
            else:
                # Hide password
                if original_text:
                    # Restore original text (without password)
                    item.setText(original_text)

            # Toggle show_password flag
            password_item["show_password"] = not password_item.get("show_password", False)


    def sort_by_website(self):
        # Sort passwords by website.
        self.passwords.sort(key=lambda x: x['website'].lower())
        self.update_password_list()

    def sort_by_username(self):
        # Sort passwords by username.
        self.passwords.sort(key=lambda x: x['username'].lower())
        self.update_password_list()

    def sort_by_datetime(self):
        # Sort passwords by date/time.
        self.passwords.sort(key=lambda x: datetime.datetime.strptime(x['timestamp'], "%Y-%m-%d %H:%M:%S"))
        self.update_password_list()

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

def generate_verification_code():
    # Generate a verification code.
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

def send_verification_email(receiver_email, verification_code):
    # Send verification email with code.
    try:
        subject = "Verification Code for Max Guard"
        message = f"""\
        <html>
            <body style="color: #333333;">
                <p>Dear User,</p>
                <p>Thank you for using Max Guard. To verify your account, please use the following verification code:</p>
                <p><strong>Verification Code: {verification_code}</strong></p>
                <p>Enter this code in the application to complete the verification process.</p>
                <p>In case you did not request this verification code, please ignore this email.</p>
                <p>Thank you,<br>Max :)</p>
            </body>
        </html>
        """
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = EMAIL_SENDER
        msg['To'] = receiver_email

        # Attach HTML message
        msg.attach(MIMEText(message, 'html'))

        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        server.login(EMAIL_SENDER, EMAIL_SENDER_PASSWORD)
        server.sendmail(EMAIL_SENDER, receiver_email, msg.as_string())
        server.quit()
        print("Verification email sent successfully.")
    except Exception as e:
        print(f"Error sending verification email: {e}")


def user_exists(username, password):
    # Check if user exists and password matches.
    try:
        obj = s3.get_object(Bucket='mgcapstonepasswordmanager', Key="users.json")
        existing_users = json.loads(obj['Body'].read().decode('utf-8'))
        if username in existing_users and existing_users[username] == password:
            return True
        else:
            return False
    except Exception as e:
        print(f"Error checking if user exists: {e}")
        return False

def verify_code(entered_code, verification_code):
    # Verify the entered code with the generated verification code.
    return entered_code == verification_code

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.setStyleSheet(dark_stylesheet)  # Set default stylesheet initially
    window.show()
    sys.exit(app.exec_())