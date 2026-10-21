from sqlalchemy.orm import Session
from phishhunter.models import Case, AuditEvent

def create_case(db: Session, tenant_id: int, title: str, priority: str="medium", notes: str=""):
    row=Case(tenant_id=tenant_id,title=title.strip(),priority=priority,notes=notes)
    db.add(row); db.flush(); db.add(AuditEvent(tenant_id=tenant_id, action="case.created", detail=f"case_id={row.id}")); db.commit(); db.refresh(row); return row

def update_case(db: Session, tenant_id: int, case_id: int, **changes):
    row=db.query(Case).filter_by(id=case_id,tenant_id=tenant_id).first()
    if not row: return None
    for k,v in changes.items():
        if v is not None and hasattr(row,k): setattr(row,k,v)
    db.add(AuditEvent(tenant_id=tenant_id, action="case.updated", detail=f"case_id={row.id}")); db.commit(); db.refresh(row); return row
