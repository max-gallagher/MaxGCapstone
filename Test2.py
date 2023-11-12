import sys
import os
import json
import random
import string
import datetime  # Import the datetime module
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QListWidget, QMessageBox, QFormLayout, QHBoxLayout, QListWidgetItem

# Create the main application window
class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 600, 200)

        # Set the login widget as the initial central widget
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

        layout.addWidget(self.username_label)
        layout.addWidget(self.username_entry)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.login_button)

        self.setLayout(layout)

    def login(self):
        username = self.username_entry.text()
        password = self.password_entry.text()

        # Check if the provided username and password exist in the user database
        if user_exists(username, password):
            # If login is successful, switch to the password manager widget
            self.parent.setCentralWidget(PasswordManagerWidget(self.parent, username))
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password. Please try again.")

# Widget for managing passwords
class PasswordManagerWidget(QWidget):
    def __init__(self, parent, username):
        super().__init__()

        self.parent = parent
        self.username = username
        self.passwords = []

        # Load stored passwords from a JSON file
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

        self.show_password_button = QPushButton("Show Passwords")
        self.show_password_button.clicked.connect(self.show_passwords)
        layout.addWidget(self.show_password_button)

        self.setLayout(layout)

    # Function to generate a random password
    def generate_password(self):
        try:
            length = int(self.length_entry.text())
            characters = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choice(characters) for _ in range(length))
            self.password_entry.setText(password)
        except ValueError:
            QMessageBox.warning(self, "Invalid Length", "Please enter a valid password length.")

    # Function to save a password entry
    def save_password(self):
        website = self.website_entry.text()
        username = self.username_entry.text()
        password = self.password_entry.text()
        
        # Get the current date and time
        current_datetime = datetime.datetime.now()

        if not website or not username or not password:
            QMessageBox.warning(self, "Error", "Please enter website, username, and password.")
            return

        # Create a password entry dictionary with a timestamp
        entry = {
            "website": website,
            "username": username,
            "password": password,
            "timestamp": current_datetime.strftime("%Y-%m-%d %H:%M:%S")  # Format the timestamp
        }
        self.passwords.append(entry)
        self.save_passwords()  # Save the updated password list to a JSON file
        self.update_password_list()  # Update the displayed password list
        self.clear_entries()  # Clear the input fields
        self.result_label.setText("Password saved successfully!")

    # Function to show or hide passwords in the list
    def show_passwords(self):
        for index in range(self.password_list.count()):
            item = self.password_list.item(index)
            password_item = self.passwords[index]
            item_text = f"Website: {password_item['website']} | Username: {password_item['username']} | Date Generated: {password_item['timestamp']} | Password: {password_item['password']}"
            item.setText(item_text)

            # Toggle the "show_password" flag
            password_item["show_password"] = not password_item.get("show_password", False)

    # Function to clear input fields
    def clear_entries(self):
        self.website_entry.clear()
        self.username_entry.clear()
        self.password_entry.clear()
        self.length_entry.clear()

    # Function to update the displayed password list
    def update_password_list(self):
        self.password_list.clear()
        for entry in self.passwords:
            item = QListWidgetItem()
            item_text = f"Website: {entry['website']} | Username: {entry['username']}"
            if 'timestamp' in entry:
                item_text += f" | Date Generated: {entry['timestamp']}"
            item.setText(item_text)
            self.password_list.addItem(item)

    # Function to load passwords from a JSON file
    def load_passwords(self):
        try:
            with open(f"{self.username}_passwords.json", "r") as file:
                self.passwords = json.load(file)
        except FileNotFoundError:
            self.passwords = []

    # Function to save passwords to a JSON file
    def save_passwords(self):
        with open(f"{self.username}_passwords.json", "w") as file:
            json.dump(self.passwords, file)

# Function to check if the provided username and password exist in the user database
def user_exists(username, password):
    users = {"testuser": "test123", "max": "password123"}  # Example user database
    return users.get(username) == password

# Main function to run the application
def main():
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()