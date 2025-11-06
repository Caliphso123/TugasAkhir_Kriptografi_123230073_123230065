import sqlite3
import os

# Lokasi file database
DB_PATH = os.path.join(os.path.dirname(__file__), "secure_storage.db")

def init_db():
    # Buat file database kalau belum ada
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Buat tabel users (untuk login)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        last_password_reset TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Buat tabel log aktivitas (opsional)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        activity TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()
    print("[OK] Database & tabel berhasil dibuat di:", DB_PATH)

if __name__ == "__main__":
    init_db()
