import hashlib
import hmac
import secrets

from fastapi import HTTPException, Request

from phishhunter.config import settings


def issue_csrf(request: Request) -> str:
    token = request.cookies.get(settings.csrf_cookie_name)
    if token and len(token) == 64:
        request.state.csrf_token = token
        return token
    token = secrets.token_hex(32)
    request.state.csrf_token = token
    request.state.set_csrf_cookie = True
    return token


def verify_csrf(request: Request, submitted: str) -> None:
    expected = request.cookies.get(settings.csrf_cookie_name) or getattr(
        request.state, "csrf_token", ""
    )
    if not submitted or not expected or not hmac.compare_digest(submitted, expected):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def signed_report_token(scan_id: int, tenant_id: int) -> str:
    message = f"report:{tenant_id}:{scan_id}".encode()
    digest = hmac.new(settings.secret_key.encode(), message, hashlib.sha256).hexdigest()
    return f"{scan_id}.{tenant_id}.{digest}"


def verify_report_token(token: str, scan_id: int, tenant_id: int) -> bool:
    expected = signed_report_token(scan_id, tenant_id)
    return hmac.compare_digest(token, expected)
