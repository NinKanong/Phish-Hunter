from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from phishhunter.db.database import get_session
from phishhunter.deps import current_user
from phishhunter.models import User, UserProfile, UserControl

router=APIRouter(prefix="/auth",tags=["auth"])

@router.get("/me")
def me(user: User=Depends(current_user), db: Session=Depends(get_session)):
    profile=db.query(UserProfile).filter_by(user_id=user.id).first()
    control=db.query(UserControl).filter_by(user_id=user.id).first()
    return {"id":user.id,"username":user.username,"email":user.email,"tenant_id":user.tenant_id,"is_admin":user.is_admin,
            "profile":{"display_name":profile.display_name if profile else "","job_title":profile.job_title if profile else "Analyst"},
            "control":{"disabled":bool(control.disabled) if control else False,"last_login_at":control.last_login_at if control else None}}

@router.post("/logout")
def logout(request: Request, user: User=Depends(current_user)):
    response={"status":"signed_out"}
    # Browser session is cleared by the existing web logout route; API callers can discard bearer tokens.
    return response
