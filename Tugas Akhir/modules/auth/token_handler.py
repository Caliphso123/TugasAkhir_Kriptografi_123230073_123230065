import jwt
import datetime

# Bisa kamu simpan di config/security.py juga nanti
SECRET_KEY = "securevault-secret-key"  

def generate_token(username: str, expire_minutes: int = 30) -> str:
    """
    Membuat JWT token berdasarkan username.
    Token ini akan kadaluarsa sesuai waktu expire_minutes.
    """
    payload = {
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=expire_minutes)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

def verify_token(token: str):
    """
    Verifikasi token JWT, mengembalikan payload jika valid.
    """
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        print("⚠️ Token expired.")
        return None
    except jwt.InvalidTokenError:
        print("❌ Token tidak valid.")
        return None


# Debug mandiri (bisa dicoba di terminal)
if __name__ == "__main__":
    t = generate_token("ekin")
    print("Token:", t)
    print("Decoded:", verify_token(t))
