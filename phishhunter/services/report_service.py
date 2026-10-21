import json
from phishhunter.models import Report

def persist_json_report(db, tenant_id: int, scan_id: int, title: str, payload: dict, owner_user_id: int | None = None):
    row=Report(tenant_id=tenant_id,owner_user_id=owner_user_id,scan_id=scan_id,title=title,format="json",content=json.dumps(payload,indent=2,default=str))
    db.add(row); db.commit(); db.refresh(row); return row
