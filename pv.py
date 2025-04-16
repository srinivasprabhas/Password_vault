# PASSWORD VAULT WITH 2FA - CLEAN STRUCTURE
import mysql.connector
from tkinter import Tk, Label, Entry, Button, Toplevel, messagebox
from tkinter.simpledialog import askstring
from tkinter.scrolledtext import ScrolledText
from functools import partial
import pkg_resources
import subprocess
import os
import secrets
import string
import base64
import pyotp
import qrcode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

# Install required packages
required_packages = ['pycryptodomex', 'pyotp', 'qrcode[pil]']
for package in required_packages:
    try:
        pkg_resources.get_distribution(package)
    except pkg_resources.DistributionNotFound:
        subprocess.check_call(['pip', 'install', package])

# --------------------------------- ENCRYPTION METHODS ---------------------------------
def encrypt_text(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return base64.b64encode(ciphertext).decode()

def decrypt_text(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(base64.b64decode(ciphertext))
    return ''.join(char for char in decrypted_bytes.decode('utf-8') if char.isprintable())

# --------------------------------- DATABASE INIT ---------------------------------
def initialize_database():
    try:
        connection = mysql.connector.connect(host="localhost", user="root", password="")
        cursor = connection.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS password_vault")
        cursor.execute("USE password_vault")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE,
                password LONGTEXT,
                totp_secret VARCHAR(255)
            )
        """)
        connection.commit()
        cursor.close()
        connection.close()
    except mysql.connector.Error as error:
        print("Failed to connect to MySQL:", error)
        messagebox.showerror("Database Error", "Could not connect to database. Make sure MySQL is running.")

# --------------------------------- ACCOUNT FUNCTIONS ---------------------------------
def check_user_exists(mail):
    try:
        connection = mysql.connector.connect(host="localhost", user="root", password="", database="password_vault")
        cursor = connection.cursor()
        cursor.execute("SELECT email FROM users WHERE email = %s", (mail,))
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        return result is not None
    except mysql.connector.Error as error:
        print("Database error:", error)
        return False

def insert_account(mail, password, totp_secret):
    try:
        connection = mysql.connector.connect(host="localhost", user="root", password="", database="password_vault")
        cursor = connection.cursor()
        cursor.execute("INSERT INTO users (email, password, totp_secret) VALUES (%s, %s, %s)", (mail, password, totp_secret))
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS `{mail}` (
                s_no INT AUTO_INCREMENT PRIMARY KEY,
                account_name VARCHAR(255),
                user_id LONGTEXT,
                password LONGTEXT
            )
        """)
        connection.commit()
        cursor.close()
        connection.close()
    except mysql.connector.Error as error:
        print("Failed to insert record:", error)

# --------------------------------- GUI: MAIN WINDOW ---------------------------------
def open_main_window(mail):
    global main_window
    main_window = Toplevel(window)
    main_window.title("Password Vault")
    main_window.geometry("250x150")

    Label(main_window, text="Password Vault", font=("Helvetica", 16)).pack(pady=10)
    Button(main_window, text="Add Passwords", command=lambda: add_password_window(mail)).pack(pady=5)
    Button(main_window, text="View Passwords", command=lambda: view_password(mail)).pack(pady=5)

# --------------------------------- GUI: SIGNUP & LOGIN ---------------------------------
def signup_window():
    global signup_mail, signup_password, signup_re_enter_password, signup_window
    signup_window = Toplevel(window)
    signup_window.title("Sign Up")
    signup_window.geometry("400x300")

    Label(signup_window, text="Email:").pack(pady=5)
    signup_mail = Entry(signup_window, width=30)
    signup_mail.pack(pady=5)

    Label(signup_window, text="Password:").pack(pady=5)
    signup_password = Entry(signup_window, width=30, show="*")
    signup_password.pack(pady=5)

    Label(signup_window, text="Re-enter Password:").pack(pady=5)
    signup_re_enter_password = Entry(signup_window, width=30, show="*")
    signup_re_enter_password.pack(pady=5)

    Button(signup_window, text="Sign Up", command=signup).pack(pady=10)

def login_window():
    global login_mail, login_password, login_window
    login_window = Toplevel(window)
    login_window.title("Login")
    login_window.geometry("400x300")

    Label(login_window, text="Email:").pack(pady=5)
    login_mail = Entry(login_window, width=30)
    login_mail.pack(pady=5)

    Label(login_window, text="Password:").pack(pady=5)
    login_password = Entry(login_window, width=30, show="*")
    login_password.pack(pady=5)

    Button(login_window, text="Login", command=login).pack(pady=10)

def signup():
    mail = signup_mail.get()
    password = signup_password.get()
    re_entered_password = signup_re_enter_password.get()

    if not mail or not password:
        messagebox.showerror("Signup Failed", "Please enter email and password")
        return

    if check_user_exists(mail):
        messagebox.showerror("Signup Failed", "Account already exists")
        return

    if len(password) < 8 or not any(char.isdigit() for char in password) or \
       not any(char.isupper() for char in password) or \
       not any(char in "!@#$%^&*()_+-=[]{}:'\"\\|,.<>/?`~" for char in password):
        messagebox.showerror("Error", "Password must be 8+ characters with capital, digit & special char")
        return

    if password != re_entered_password:
        messagebox.showerror("Signup Failed", "Passwords do not match")
        return

    key = (mail + '0'*16)[:16].encode()
    encrypted_password = encrypt_text(key, password)
    totp_secret = pyotp.random_base32()

    insert_account(mail, encrypted_password, totp_secret)

    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(name=mail, issuer_name="PasswordVault")
    qrcode.make(uri).show()

    signup_window.destroy()
    messagebox.showinfo("Signup Successful", "Scan the QR code in Authenticator app.")

def login():
    global mail
    try:
        mail = login_mail.get()
        password = login_password.get()
    except Exception:
        messagebox.showerror("Error", "Login window closed or destroyed.")
        return

    if not mail or not password:
        messagebox.showerror("Login Failed", "Enter email and password")
        return

    try:
        connection = mysql.connector.connect(host="localhost", user="root", password="", database="password_vault")
        cursor = connection.cursor()
        cursor.execute("SELECT password, totp_secret FROM users WHERE email = %s", (mail,))
        result = cursor.fetchone()
        cursor.close()
        connection.close()

        if not result:
            messagebox.showerror("Login Failed", "Invalid Email")
            return

        db_password, totp_secret = result
        key = (mail + '0'*16)[:16].encode()
        encrypted_password = encrypt_text(key, password)

        if encrypted_password != db_password:
            messagebox.showerror("Login Failed", "Invalid Password")
            return

        totp = pyotp.TOTP(totp_secret)
        code = askstring("2FA", "Enter 6-digit code from Authenticator app")

        if not totp.verify(code):
            messagebox.showerror("2FA Failed", "Invalid code")
            return

        login_window.destroy()
        open_main_window(mail)

    except mysql.connector.Error as error:
        print("Database error:", error)
        messagebox.showerror("Login Failed", "Database connection error")

# --------------------------------- PASSWORD MANAGEMENT ---------------------------------
def add_password_window(mail):
    global site_entry, username_entry, password_entry, store_window
    store_window = Toplevel(window)
    store_window.title("Add Password")
    store_window.geometry("400x300")

    Label(store_window, text="Site/App Name:").pack(pady=5)
    site_entry = Entry(store_window, width=30)
    site_entry.pack(pady=5)

    Label(store_window, text="Username:").pack(pady=5)
    username_entry = Entry(store_window, width=30)
    username_entry.pack(pady=5)

    Label(store_window, text="Password:").pack(pady=5)
    password_entry = Entry(store_window, width=30, show="*")
    password_entry.pack(pady=5)

    Button(store_window, text="Save", command=lambda: store_details(mail)).pack(pady=10)

def store_details(mail):
    try:
        site = site_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        if not site or not username or not password:
            messagebox.showerror("Error", "All fields are required")
            return

        connection = mysql.connector.connect(host="localhost", user="root", password="", database="password_vault")
        key = (mail + '0'*16)[:16].encode()
        username_enc = encrypt_text(key, username)
        password_enc = encrypt_text(key, password)

        cursor = connection.cursor()
        cursor.execute(f"INSERT INTO `{mail}` (account_name, user_id, password) VALUES (%s, %s, %s)", (site, username_enc, password_enc))
        connection.commit()
        cursor.close()
        connection.close()

        store_window.destroy()
        messagebox.showinfo("Saved", "Password stored successfully.")
    except mysql.connector.Error as error:
        print("Error storing password:", error)
        messagebox.showerror("Error", "Database error while saving.")

def view_password(mail):
    try:
        main_window.destroy()
        view_window = Toplevel(window)
        view_window.title("Saved Passwords")
        view_window.geometry("600x400")

        result_text = ScrolledText(view_window, height=15, width=70, bg="white")
        result_text.pack()

        connection = mysql.connector.connect(host="localhost", user="root", password="", database="password_vault")
        cursor = connection.cursor()
        cursor.execute(f"SELECT * FROM `{mail}`")
        records = cursor.fetchall()

        key = (mail + '0'*16)[:16].encode()

        result_text.insert('end', f"{'S.No.':<6} {'Site':<20} {'Username':<25} {'Password'}\n")
        result_text.insert('end', "="*70 + "\n")

        for i, row in enumerate(records, start=1):
            decrypted_user = decrypt_text(key, row[2])
            decrypted_pass = decrypt_text(key, row[3])
            result_text.insert('end', f"{i:<6} {row[1]:<20} {decrypted_user:<25} {decrypted_pass}\n")

        cursor.close()
        connection.close()

        Button(view_window, text="Back", command=lambda: back_to_main(mail, view_window)).pack(pady=10)
    except mysql.connector.Error as error:
        print("Error retrieving passwords:", error)
        messagebox.showerror("Error", "Could not fetch passwords.")

def back_to_main(mail, current_window):
    current_window.destroy()
    open_main_window(mail)

# --------------------------------- MAIN GUI ---------------------------------
initialize_database()
window = Tk()
window.title("Password Vault")
window.geometry("300x200")

Label(window, text="Password Vault", font=("Helvetica", 16)).pack(pady=10)
Button(window, text="Sign Up", command=signup_window).pack(pady=10)
Button(window, text="Login", command=login_window).pack(pady=10)

window.mainloop()
