import os
import hashlib
from argon2 import PasswordHasher, low_level, Type as Argon2Type
from argon2.low_level import hash_secret
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import string
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import hmac

ph = PasswordHasher(type=Argon2Type.ID)

def hash_password(password: str) -> str:
    """Menghash password menggunakan Argon2id untuk disimpan di server."""
    return ph.hash(password)

def verify_password(hashed_password: str, password: str) -> bool:
    """Memverifikasi password pengguna saat login."""
    try:
        ph.verify(hashed_password, password)
        return True
    except Exception:
        return False

def generate_salt(length: int = 16) -> bytes:
    """Menghasilkan salt unik (per pengguna) untuk Key Derivation."""
    return os.urandom(length)

def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """
    Menderivasi Kunci Utama Pengguna (UMK) dari password dan salt menggunakan Argon2id.
    Output: 32 bytes (AES-256 key).
    """
    key_bytes_full = hash_secret(
        secret=password.encode('utf-8'),
        salt=salt,  
        time_cost=4,             
        memory_cost=65536,       
        parallelism=4,
        hash_len=length,         
        type=Argon2Type.ID,      
    )

    key_bytes = low_level.hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt, 
        time_cost=4,
        memory_cost=65536,
        parallelism=4,
        hash_len=length, 
        type=low_level.Type.ID 
    )
    return key_bytes 

def encrypt_data(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Mengenripsi data biner menggunakan AES-256 GCM."""

    nonce = os.urandom(12) 
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    
    return ciphertext + tag, nonce

def decrypt_data(key: bytes, encrypted_content: bytes, nonce: bytes) -> bytes:
    """Mendekripsi data biner menggunakan AES-256 GCM dan memverifikasi tag."""
    
    TAG_LENGTH = 16 
    
    ciphertext = encrypted_content[:-TAG_LENGTH]
    tag = encrypted_content[-TAG_LENGTH:]
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    return decrypted_data

def hash_user_id(user_id: int) -> str:
    """Menghash ID numerik pengguna menjadi string unik menggunakan SHA256."""
    return hashlib.sha256(str(user_id).encode()).hexdigest()

def generate_secret_code(length=10):
    """Menghasilkan kode alfanumerik acak 10 karakter."""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for i in range(length))

def hash_secret_code(code: str, salt: bytes) -> bytes:
    """Menghasilkan hash dari kode rahasia (untuk disimpan/verifikasi) menggunakan salt."""
    return hashlib.pbkdf2_hmac('sha256', code.encode('utf-8'), salt, 100000, dklen=32)

def verify_secret_code(input_code: str, stored_hash: bytes, stored_salt: bytes) -> bool:
    """
    Memverifikasi kode yang dimasukkan oleh pengguna dengan hash yang tersimpan,
    menggunakan salt yang tersimpan.
    """
    if not stored_salt or not stored_hash:
        return False
        
    input_hash = hash_secret_code(input_code, stored_salt)
    
    return hmac.compare_digest(input_hash, stored_hash)

def derive_shared_key(secret_code: str, salt: bytes) -> bytes:
    secret_bytes = secret_code.encode('utf-8')
    
    kdf = Scrypt(
        salt=salt,
        length=32,          
        n=2**14,            
        r=8,                
        p=1,                
        backend=default_backend()
    )
    
    shared_key = kdf.derive(secret_bytes)
    return shared_key