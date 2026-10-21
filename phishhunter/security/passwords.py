from argon2 import PasswordHasher

_hasher=PasswordHasher()

def hash_password(password: str) -> str:
    return _hasher.hash(password)

def verify_password(password: str, digest: str) -> bool:
    try:
        return _hasher.verify(digest, password)
    except Exception:
        return False
