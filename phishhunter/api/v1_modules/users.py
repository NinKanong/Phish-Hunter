from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from phishhunter.db.database import get_session
from phishhunter.deps import current_user
from phishhunter.models import User, UserProfile, UserControl, Tenant, AuditEvent, UserActivity
from phishhunter.security.passwords import hash_password

router=APIRouter(prefix="/users",tags=["users"])

class UserCreate(BaseModel):
    email: str
    username: str
    password: str=Field(min_length=8,max_length=256)
    display_name: str=""
    job_title: str="Analyst"
    tenant_id: int|None=None
    is_admin: bool=False

class UserUpdate(BaseModel):
    display_name: str|None=None
    job_title: str|None=None
    disabled: bool|None=None
    is_admin: bool|None=None


def admin_only(user: User):
    if not user.is_admin: raise HTTPException(403,"Administrator role required")

@router.get("")
def list_users(user: User=Depends(current_user),db:Session=Depends(get_session)):
    admin_only(user)
    rows=db.query(User).filter(User.tenant_id==user.tenant_id).order_by(User.id.desc()).all()
    controls={r.user_id:r for r in db.query(UserControl).filter(UserControl.user_id.in_([x.id for x in rows])).all()}
    profiles={r.user_id:r for r in db.query(UserProfile).filter(UserProfile.user_id.in_([x.id for x in rows])).all()}
    return [{"id":r.id,"username":r.username,"email":r.email,"tenant_id":r.tenant_id,"is_admin":r.is_admin,"created_at":r.created_at,
             "disabled":bool(controls.get(r.id).disabled) if controls.get(r.id) else False,
             "display_name":profiles.get(r.id).display_name if profiles.get(r.id) else "",
             "job_title":profiles.get(r.id).job_title if profiles.get(r.id) else "Analyst"} for r in rows]

@router.post("")
def create_user(payload:UserCreate,user:User=Depends(current_user),db:Session=Depends(get_session)):
    admin_only(user)
    if db.query(User).filter_by(email=payload.email.lower().strip()).first(): raise HTTPException(409,"Email already exists")
    username=payload.username.lower().strip()
    if db.query(User).filter(User.username == username).first(): raise HTTPException(409,"Username already exists")
    if not (3 <= len(username) <= 64) or any(not (c.isalnum() or c in "._-") for c in username): raise HTTPException(400,"Invalid username")
    tenant_id=user.tenant_id
    row=User(tenant_id=tenant_id,username=username,email=payload.email.lower().strip(),password_hash=hash_password(payload.password),is_admin=payload.is_admin)
    db.add(row); db.flush()
    profile = db.query(UserProfile).filter_by(user_id=row.id).first()
    if profile:
        profile.display_name = payload.display_name
        profile.job_title = payload.job_title
        db.add(profile)
    else:
        db.add(UserProfile(user_id=row.id,display_name=payload.display_name,job_title=payload.job_title))
    control = db.query(UserControl).filter_by(user_id=row.id).first()
    if control:
        control.disabled = False
        control.failed_logins = 0
        db.add(control)
    else:
        db.add(UserControl(user_id=row.id))
    db.add(AuditEvent(tenant_id=user.tenant_id,action="admin.user.created",detail=f"user_id={row.id}"))
    db.add(UserActivity(user_id=row.id, actor_user_id=user.id, event_type="account", action="account.created_by_admin_api", detail=f"Account created through administrator API by user #{user.id}", metadata_json={"role": "admin" if payload.is_admin else "analyst"}))
    db.commit(); db.refresh(row)
    return {"id":row.id,"username":row.username,"email":row.email,"tenant_id":row.tenant_id,"is_admin":row.is_admin}

@router.patch("/{user_id}")
def update_user(user_id:int,payload:UserUpdate,user:User=Depends(current_user),db:Session=Depends(get_session)):
    admin_only(user); row=db.query(User).filter_by(id=user_id,tenant_id=user.tenant_id).first()
    if not row: raise HTTPException(404,"User not found")
    if payload.is_admin is not None: row.is_admin=payload.is_admin
    p=db.query(UserProfile).filter_by(user_id=row.id).first() or UserProfile(user_id=row.id)
    c=db.query(UserControl).filter_by(user_id=row.id).first() or UserControl(user_id=row.id)
    if payload.display_name is not None: p.display_name=payload.display_name
    if payload.job_title is not None: p.job_title=payload.job_title
    if payload.disabled is not None: c.disabled=payload.disabled
    db.add_all([p,c]); db.add(AuditEvent(tenant_id=user.tenant_id,action="admin.user.updated",detail=f"user_id={row.id}")); db.add(UserActivity(user_id=row.id, actor_user_id=user.id, event_type="account", action="account.updated_by_admin_api", detail=f"Account updated through administrator API by user #{user.id}")); db.commit()
    return {"status":"updated","id":row.id}
