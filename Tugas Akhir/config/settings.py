import os

# Root path
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# Paths
DB_PATH = os.path.join(BASE_DIR, "database", "secure_storage.db")
KEYS_DIR = os.path.join(BASE_DIR, "keys")

# Mode
DEBUG = True
