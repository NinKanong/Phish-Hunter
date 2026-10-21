from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from phishhunter.db.database import get_session
from phishhunter.deps import current_user
from phishhunter.models import IOC, User
router=APIRouter(prefix="/iocs",tags=["iocs"])
@router.get("")
def list_iocs(user:User=Depends(current_user),db:Session=Depends(get_session)):
    query=db.query(IOC).filter(IOC.tenant_id == user.tenant_id)
    if not user.is_admin:
        query=query.filter(IOC.owner_user_id == user.id)
    rows=query.order_by(IOC.id.desc()).limit(1000).all()
    return [{"id":x.id,"kind":x.kind,"value":x.value,"source_scan_id":x.source_scan_id,"created_at":x.created_at} for x in rows]
