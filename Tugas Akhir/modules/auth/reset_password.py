import sqlite3
import os
import secrets
from datetime import datetime, UTC
from argon2 import PasswordHasher

# Lokasi database (pastikan path ini benar relatif terhadap file kamu)
DB_PATH = os.path.join(os.path.dirname(__file__), "../../database/secure_storage.db")

# Inisialisasi Argon2 untuk hashing password
ph = PasswordHasher()

def generate_random_password(length=6):
    """
    Menghasilkan password acak yang aman.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-="
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def set_user_password(username, new_password):
    """
    Mengganti password user dengan password baru (dihash menggunakan Argon2).
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Cek apakah user ada di database
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if not result:
        print("[!] Username tidak ditemukan.")
        conn.close()
        return False

    # Hash password baru
    hashed_pw = ph.hash(new_password)

    # Update password user dan waktu reset
    cursor.execute("""
        UPDATE users
        SET password_hash = ?, last_password_reset = ?
        WHERE username = ?
    """, (hashed_pw, datetime.now(UTC).isoformat(), username))

    conn.commit()
    conn.close()

    print(f"[OK] Password untuk user '{username}' berhasil direset.")
    return True

def reset_password_menu():
    """
    Menu CLI sederhana untuk admin melakukan reset password.
    """
    print("=== Reset Password System (Admin Mode) ===")
    username = input("Masukkan username yang ingin direset: ")

    choice = input("Ingin buat password acak otomatis? (y/n): ").lower()
    if choice == 'y':
        new_pw = generate_random_password()
        print(f"[INFO] Password baru otomatis untuk '{username}': {new_pw}")
    else:
        new_pw = input("Masukkan password baru secara manual: ")

    if set_user_password(username, new_pw):
        print("[✓] Reset password berhasil.")
        print("Silakan berikan password baru ke pengguna secara aman.")
    else:
        print("[✗] Reset gagal. Cek kembali username.")

# Jalankan langsung untuk uji coba mandiri
if __name__ == "__main__":
    reset_password_menu()
