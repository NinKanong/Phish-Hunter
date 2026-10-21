from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from phishhunter.db.database import get_session
from phishhunter.deps import current_user
from phishhunter.models import Report, User
router=APIRouter(prefix="/reports",tags=["reports"])
@router.get("")
def list_reports(user:User=Depends(current_user),db:Session=Depends(get_session)):
    query=db.query(Report).filter(Report.tenant_id == user.tenant_id)
    if not user.is_admin:
        query=query.filter(Report.owner_user_id == user.id)
    rows=query.order_by(Report.id.desc()).limit(500).all()
    return [{"id":r.id,"scan_id":r.scan_id,"title":r.title,"format":r.format,"created_at":r.created_at} for r in rows]
@router.get("/{report_id}")
def get_report(report_id:int,user:User=Depends(current_user),db:Session=Depends(get_session)):
    query=db.query(Report).filter(Report.id == report_id, Report.tenant_id == user.tenant_id)
    if not user.is_admin:
        query=query.filter(Report.owner_user_id == user.id)
    row=query.first()
    if not row: raise HTTPException(404,"Report not found")
    return {"id":row.id,"scan_id":row.scan_id,"title":row.title,"format":row.format,"content":row.content,"created_at":row.created_at}
