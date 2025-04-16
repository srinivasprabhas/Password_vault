# Password_vault
# 🔐 Password Vault with 2FA (Python + Tkinter + MySQL)

A secure, user-friendly desktop application built using Python to store and manage your passwords with AES encryption and Two-Factor Authentication (2FA).

---

## 🚀 Features

- 🔐 AES encryption for all stored credentials
- 👤 Sign up / Login with email and password
- ✅ TOTP-based 2FA (compatible with Google Authenticator)
- 🧾 Store and view saved passwords (encrypted)
- 📦 MySQL-based data storage
- 🎨 Built with Tkinter GUI

---

## 🛠️ Tech Stack

| Category        | Tools/Libraries                     |
|----------------|--------------------------------------|
| Language        | Python                              |
| GUI             | Tkinter                             |
| Database        | MySQL                               |
| Encryption      | AES via `pycryptodomex`             |
| 2FA             | `pyotp`, `qrcode[pil]`              |
| DB Connector    | `mysql-connector-python`            |

---

## 🧰 Requirements

- Python 3.7+
- MySQL Server
- The following Python packages (auto-installed):
  - `pycryptodomex`
  - `pyotp`
  - `qrcode[pil]`
  - `mysql-connector-python`

---

![Sample output1](https://github.com/srinivasprabhas/Password_vault/blob/main/pv_execution.mp4)

## ⚙️ Setup Instructions



1. **Clone the repository**

```bash
git clone https://github.com/yourusername/password-vault.git
cd password-vault

2. **Clone the repository**
pip install -r requirements.txt

3. Ensure MySQL is running, and create the database (auto-created on first run).

4. Run the application
pyhton pv.py






