import tkinter as tk
from tkinter import simpledialog, messagebox, font, Label, Entry, Button
import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os
import string
import random

# Constants for login credentials
LOGIN_USER = "admin"
LOGIN_PASS = "password"

# Database setup - Initializes or connects to the SQLite database and creates the table if it doesn't exist
def initialize_db():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (service TEXT PRIMARY KEY, password TEXT)''')
    conn.commit()
    conn.close()

# Encryption Key - Generates and saves a new encryption key if it doesn't exist
def generate_key():
    key = get_random_bytes(16)  # AES key must be either 16, 24, or 32 bytes
    with open("key.key", "wb") as key_file:
        key_file.write(key)

# Check if encryption key exists, if not, generate one
if not os.path.exists('key.key'):
    generate_key()

# Load the encryption key
with open("key.key", "rb") as key_file:
    key = key_file.read()

# Initialize the database
initialize_db()

# Encryption and decryption functions for messages
def encrypt_message(message):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_message(enc_message):
    data = base64.b64decode(enc_message)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Execute SQL command with error handling
def execute_db_command(command, params=()):
    try:
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute(command, params)
        result = None
        if command.strip().upper().startswith("SELECT"):
            result = c.fetchone()
        conn.commit()
        return result
    except sqlite3.Error as e:
        messagebox.showerror("Database Error", str(e))
        return None
    finally:
        conn.close()

# CRUD operations for passwords
def add_password(service, password):
    encrypted_password = encrypt_message(password)
    execute_db_command('INSERT INTO passwords VALUES (?, ?)', (service, encrypted_password))

def get_password(service):
    result = execute_db_command('SELECT password FROM passwords WHERE service=?', (service,))
    if result:
        return decrypt_message(result[0])
    return None

def update_password(service, new_password):
    encrypted_password = encrypt_message(new_password)
    execute_db_command('UPDATE passwords SET password = ? WHERE service = ?', (encrypted_password, service))

def delete_password(service):
    execute_db_command('DELETE FROM passwords WHERE service=?', (service,))

# Generates a random password
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

# Login Window Class
class LoginWindow:
    def __init__(self, parent):
        self.parent = parent
        self.window = tk.Toplevel(parent.root)
        self.window.title("Login")
        self.window.geometry('300x150')
        self.window.resizable(False, False)

        # Login form fields
        Label(self.window, text="Username:").pack(pady=5)
        self.username_entry = Entry(self.window)
        self.username_entry.pack(pady=5)

        Label(self.window, text="Password:").pack(pady=5)
        self.password_entry = Entry(self.window, show="*")
        self.password_entry.pack(pady=5)

        # Login button
        Button(self.window, text="Login", command=self.check_login).pack(pady=10)

        # Handle closing of login window
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)

    # Check credentials on login
    def check_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username == LOGIN_USER and password == LOGIN_PASS:
            self.window.destroy()
            self.parent.initialize_ui()
        else:
            messagebox.showerror("Login Failed", "Incorrect username or password")

    # Handle closing of login window
    def on_closing(self):
        self.parent.root.destroy()

# Main Application Class
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry('1000x1000')
        self.root.resizable(True, True)
        self.root.withdraw()  # Hide the main window initially

        # Initialize login window
        self.login_window = LoginWindow(self)

    # Initialize the main application UI
    def initialize_ui(self):
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Create and place buttons
        initial_font = font.Font(size=12)
        self.add_button = tk.Button(self.root, text="Add Password", command=self.add_password, font=initial_font)
        self.get_button = tk.Button(self.root, text="Get Password", command=self.get_password, font=initial_font)
        self.update_button = tk.Button(self.root, text="Update Password", command=self.update_password, font=initial_font)
        self.delete_button = tk.Button(self.root, text="Delete Password", command=self.delete_password, font=initial_font)

        self.add_button.grid(row=0, column=0, sticky="nsew")
        self.get_button.grid(row=1, column=0, sticky="nsew")
        self.update_button.grid(row=2, column=0, sticky="nsew")
        self.delete_button.grid(row=3, column=0, sticky="nsew")

        # Bind resize event
        self.root.bind('<Configure>', self.on_resize)

        # Show the main window
        self.root.deiconify()

    # Adjust button sizes dynamically on resize
    def on_resize(self, event):
        new_size = max(12, int(min(self.root.winfo_width(), self.root.winfo_height()) / 50))
        new_font = font.Font(size=new_size)
        self.add_button.config(font=new_font)
        self.get_button.config(font=new_font)
        self.update_button.config(font=new_font)
        self.delete_button.config(font=new_font)

    # Functions for adding, retrieving, updating, and deleting passwords
    def add_password(self):
        service = simpledialog.askstring("Input", "Enter the service name:", parent=self.root)
        if service:
            password = simpledialog.askstring("Input", "Enter the password (leave blank for random password):", parent=self.root)
            if not password:
                password = generate_random_password()
                messagebox.showinfo("Generated Password", f"Generated Password: {password}")
            add_password(service, password)
            messagebox.showinfo("Info", "Password added successfully.")
        else:
            messagebox.showerror("Error", "Service name is required")

    def get_password(self):
        service = simpledialog.askstring("Input", "Enter the service name:", parent=self.root)
        if service:
            password = get_password(service)
            if password:
                messagebox.showinfo("Info", f"Password for {service}: {password}")
            else:
                messagebox.showerror("Error", "Password not found or an error occurred.")
        else:
            messagebox.showerror("Error", "Service name is required")

    def update_password(self):
        service = simpledialog.askstring("Input", "Enter the service name:", parent=self.root)
        if service:
            new_password = simpledialog.askstring("Input", "Enter the new password:", parent=self.root)
            update_password(service, new_password)
            messagebox.showinfo("Info", "Password updated successfully.")
        else:
            messagebox.showerror("Error", "Service name is required")

    def delete_password(self):
        service = simpledialog.askstring("Input", "Enter the service name:", parent=self.root)
        if service:
            delete_password(service)
            messagebox.showinfo("Info", "Password deleted successfully.")
        else:
            messagebox.showerror("Error", "Service name is required")

# Start the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()