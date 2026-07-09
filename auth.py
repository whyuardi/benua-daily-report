"""
Auth module — JWT + PIN hashing
Uses hashlib.pbkdf2_hmac (pure Python) instead of bcrypt to avoid C ext issues on Vercel
"""
import os
import hashlib
import base64
import datetime
import jwt

SECRET_KEY = os.environ.get('JWT_SECRET', 'bge-daily-report-secret-key-2024')

def hash_pin(pin: str) -> str:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt, 100_000)
    return base64.b64encode(salt + key).decode()

def verify_pin(pin: str, hashed: str) -> bool:
    try:
        raw = base64.b64decode(hashed.encode())
        salt = raw[:16]
        key = raw[16:]
        new_key = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt, 100_000)
        return key == new_key
    except Exception:
        return False

def create_token(user_id: int, role: str, phone: str) -> str:
    payload = {
        'user_id': user_id,
        'role': role,
        'phone': phone,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30),
        'iat': datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
