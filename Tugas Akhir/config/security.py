from modules.utils.key_utils import generate_aes_key, generate_rsa_keypair, save_key
import os
from config.settings import KEYS_DIR

def initialize_security():
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
    aes_key = generate_aes_key()
    priv, pub = generate_rsa_keypair()
    save_key(os.path.join(KEYS_DIR, "aes.key"), aes_key)
    save_key(os.path.join(KEYS_DIR, "rsa_private.pem"), priv)
    save_key(os.path.join(KEYS_DIR, "rsa_public.pem"), pub)
