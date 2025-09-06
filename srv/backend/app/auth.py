from passlib.context import CryptContext
from fastapi.responses import Response

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_session_cookie(response: Response, username: str, key: str):
    response.set_cookie(
        key=key,
        value=username,
        max_age=8 * 60 * 60,  # 8 hours
        httponly=True,
        samesite="lax",
        path="/"
    )

def delete_session_cookie(response: Response, key: str):
    response.delete_cookie(key=key, path="/")
