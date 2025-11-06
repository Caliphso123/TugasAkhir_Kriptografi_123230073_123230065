# modules/auth/login_manager.py
import sqlite3
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from modules.auth.token_handler import generate_token  # Import token handler (pastikan file-nya sudah ada)

# Path database
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../database/secure_storage.db"))

ph = PasswordHasher()


def register_user(username: str, password: str) -> bool:
    """Mendaftarkan user baru dengan hash Argon2"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            print("[!] Username sudah terdaftar.")
            return False

        hashed_pw = ph.hash(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()

    print(f"[+] User '{username}' berhasil didaftarkan.")
    return True


def login_user(username: str, password: str):
    """Login user dan menghasilkan JWT token jika berhasil"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if not result:
            print("[!] Username tidak ditemukan.")
            return None

        stored_hash = result[0]
        try:
            ph.verify(stored_hash, password)
            token = generate_token(username)
            print(f"[✓] Login berhasil. Selamat datang, {username}!")
            print(f"[🔑] Token Anda: {token}")
            return token
        except VerifyMismatchError:
            print("[✗] Password salah.")
            return None


def interactive_menu():
    """Antarmuka CLI untuk testing register & login"""
    print("=== SecureVault+ Login System ===")
    print("1. Register")
    print("2. Login")
    choice = input("Pilih (1/2): ").strip()

    if choice == "1":
        user = input("Masukkan username baru: ").strip()
        pw = input("Masukkan password: ").strip()
        register_user(user, pw)
    elif choice == "2":
        user = input("Masukkan username: ").strip()
        pw = input("Masukkan password: ").strip()
        login_user(user, pw)
    else:
        print("[!] Pilihan tidak valid.")


# Jalankan hanya jika file dieksekusi langsung
if __name__ == "__main__":
    interactive_menu()
