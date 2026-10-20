
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from core.config import config

TOKEN_TYPE_ACCESS = 'access'
TOKEN_TYPE_REFRESH = 'refresh'

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def hash_password(password: str) -> str:
    """
    Возвращает хеш пароля с Pepper.
    """
    password_with_pepper = f"{password}{config.PASSWORD_PEPPER}"
    return pwd_context.hash(password_with_pepper)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Проверяет соответствие введенного пароля сохраненному хешу.
    """
    password_with_pepper = f"{plain_password}{config.PASSWORD_PEPPER}"
    return pwd_context.verify(password_with_pepper, hashed_password)

def get_password_hash(password: str) -> str:
    """Хеширует пароль с добавлением секрета (pepper)."""
    password_with_pepper = f"{password}{config.PASSWORD_PEPPER}"
    return pwd_context.hash(password_with_pepper)


def _create_token(
    user_id: str, token_type: str, lifetime: timedelta,
    is_superuser: bool, version: int = 1,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        'sub': user_id,
        'jti': str(uuid.uuid4()),
        'type': token_type,
        'is_superuser': is_superuser,
        'ver': version,
        'iat': now,
        'exp': now + lifetime,
    }
    return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm=config.JWT_ALGORITHM)


def create_access_token(user_id: str, is_superuser: bool = False, version: int = 1) -> str:
    return _create_token(
        user_id, TOKEN_TYPE_ACCESS,
        timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES),
        is_superuser, version,
    )


def create_refresh_token(user_id: str, is_superuser: bool = False, version: int = 1) -> str:
    return _create_token(
        user_id, TOKEN_TYPE_REFRESH,
        timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS),
        is_superuser, version,
    )


def decode_token(token: str) -> dict:
    """Валидирует подпись и срок. Бросает jwt.PyJWTError при ошибке."""
    return jwt.decode(
        token, config.JWT_SECRET_KEY, algorithms=[config.JWT_ALGORITHM],
    )