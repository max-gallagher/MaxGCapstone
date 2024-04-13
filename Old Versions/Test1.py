import tkinter as tk
import random
import string

# Function to generate a random password that follows security guidelines
def generate_password():
    length = int(length_entry.get())
    
    if length < 8:
        result_label.config(text="Password length must be at least 8 characters")
    else:
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        
        # Ensure at least one of each character type
        while not (any(c.islower() for c in password) and
                   any(c.isupper() for c in password) and
                   any(c.isdigit() for c in password) and
                   any(c in string.punctuation for c in password)):
            password = ''.join(random.choice(characters) for _ in range(length))
        
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)

# Function to save the generated password, website, and username to a file
def save_password():
    website = website_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    
    if not website or not username or not password:
        result_label.config(text="Please enter website, username, and password.")
        return
    
    with open("passwords.txt", "a") as file:
        file.write(f"Website: {website}\n")
        file.write(f"Username: {username}\n")
        file.write(f"Password: {password}\n")
        file.write("\n")
    
    result_label.config(text="Password saved successfully!")

# Create the main window
window = tk.Tk()
window.title("Password Manager")
window.geometry("400x300")  # Larger GUI

# Create and configure GUI components
title_label = tk.Label(window, text="Password Manager", font=("Helvetica", 16))
title_label.pack(pady=10)

website_label = tk.Label(window, text="Website:", font=("Helvetica", 12))
website_label.pack()

website_entry = tk.Entry(window, font=("Helvetica", 12))
website_entry.pack()

username_label = tk.Label(window, text="Username:", font=("Helvetica", 12))
username_label.pack()

username_entry = tk.Entry(window, font=("Helvetica", 12))
username_entry.pack()

length_label = tk.Label(window, text="Password Length:", font=("Helvetica", 12))
length_label.pack()

length_entry = tk.Entry(window, font=("Helvetica", 12))
length_entry.pack()

generate_button = tk.Button(window, text="Generate Password", command=generate_password, font=("Helvetica", 12))
generate_button.pack(pady=10)

password_entry = tk.Entry(window, show="*", font=("Helvetica", 12))
password_entry.pack()

save_button = tk.Button(window, text="Save Password", command=save_password, font=("Helvetica", 12))
save_button.pack(pady=10)

result_label = tk.Label(window, text="", font=("Helvetica", 12))
result_label.pack()

# Start the GUI event loop
window.mainloop()
