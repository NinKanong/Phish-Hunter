from datetime import datetime, timedelta, timezone
import jwt
from phishhunter.config import settings

ALGORITHM="HS256"

def create_token(subject: str, token_type: str, lifetime: timedelta) -> str:
    now=datetime.now(timezone.utc)
    payload={"sub":subject,"type":token_type,"iat":now,"exp":now+lifetime}
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)

def create_access_token(subject: str)->str:
    return create_token(subject,"access",timedelta(minutes=settings.access_token_minutes))

def create_refresh_token(subject: str)->str:
    return create_token(subject,"refresh",timedelta(days=settings.refresh_token_days))

def decode_token(token: str, expected_type: str):
    data=jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    if data.get("type") != expected_type:
        raise ValueError("invalid token type")
    return data
