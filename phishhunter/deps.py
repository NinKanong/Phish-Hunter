from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from phishhunter.db.database import get_session
from phishhunter.models import User, UserControl
from phishhunter.security.jwt import decode_token


def current_user(request: Request, db: Session = Depends(get_session)) -> User:
    cookie_token = request.cookies.get("access_token")
    authorization = request.headers.get("Authorization", "")
    bearer_token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    token = cookie_token or bearer_token
    request.state.auth_via_cookie = bool(cookie_token and not bearer_token)
    if not token:
        raise HTTPException(401, "Authentication required")
    try:
        data = decode_token(token, "access")
        user_id = int(data["sub"])
    except (Exception, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(401, "Invalid token") from exc
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(401, "User not found")
    control = db.query(UserControl).filter_by(user_id=user.id).first()
    if control and control.disabled:
        raise HTTPException(403, "Account disabled")
    return user
