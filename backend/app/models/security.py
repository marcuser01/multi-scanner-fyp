import os
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from app.core.config import settings

# 1. JWT Config
SECRET_KEY = os.getenv("JWT_SECRET", "fyp-secure-jwt-secret-key-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 240

# 2. Fernet Master Key for AES Encryption
FERNET_KEY_FILE = os.path.join(os.path.dirname(settings.DATABASE_URL.replace("sqlite:///", "")), ".fernet.key")

def get_or_create_fernet_key():
    if os.path.exists(FERNET_KEY_FILE):
        with open(FERNET_KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(FERNET_KEY_FILE), exist_ok=True)
    with open(FERNET_KEY_FILE, "wb") as f:
        f.write(key)
    return key

fernet = Fernet(get_or_create_fernet_key())
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def encrypt_secret(secret: str) -> str:
    return fernet.encrypt(secret.encode()).decode()

def decrypt_secret(encrypted_secret: str) -> str:
    return fernet.decrypt(encrypted_secret.encode()).decode()