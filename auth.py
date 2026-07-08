"""
Auth module — JWT + PIN hashing
"""
import os
import datetime
import jwt
from passlib.hash import bcrypt

SECRET_KEY = os.environ.get('JWT_SECRET', 'bge-daily-report-secret-key-2024')

def hash_pin(pin: str) -> str:
    return bcrypt.hash(pin)

def verify_pin(pin: str, hashed: str) -> bool:
    return bcrypt.verify(pin, hashed)

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
