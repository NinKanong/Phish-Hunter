from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from phishhunter.db.database import get_session
from phishhunter.deps import current_user
from phishhunter.models import User, Case, CaseScan, CaseArtifact, Scan, Artifact, AuditEvent

router=APIRouter(prefix="/cases",tags=["cases"])
class CaseCreate(BaseModel): title:str=Field(min_length=2,max_length=255); priority:str="medium"; notes:str=""
class CaseUpdate(BaseModel): status:str|None=None; priority:str|None=None; notes:str|None=None; title:str|None=None

@router.get("")
def list_cases(user:User=Depends(current_user),db:Session=Depends(get_session)):
    query=db.query(Case).filter(Case.tenant_id == user.tenant_id)
    if not user.is_admin:
        query=query.filter(Case.owner_user_id == user.id)
    rows=query.order_by(Case.id.desc()).all()
    return [{"id":x.id,"title":x.title,"status":x.status,"priority":x.priority,"notes":x.notes,"created_at":x.created_at} for x in rows]

@router.post("")
def create_case(payload:CaseCreate,user:User=Depends(current_user),db:Session=Depends(get_session)):
    row=Case(tenant_id=user.tenant_id,owner_user_id=user.id,title=payload.title,priority=payload.priority,notes=payload.notes); db.add(row); db.flush(); db.add(AuditEvent(tenant_id=user.tenant_id,action="case.created",detail=f"case_id={row.id}")); db.commit(); db.refresh(row); return {"id":row.id,"title":row.title,"status":row.status,"priority":row.priority}

@router.get("/{case_id}")
def get_case(case_id:int,user:User=Depends(current_user),db:Session=Depends(get_session)):
    query=db.query(Case).filter(Case.id == case_id, Case.tenant_id == user.tenant_id)
    if not user.is_admin:
        query=query.filter(Case.owner_user_id == user.id)
    row=query.first()
    if not row: raise HTTPException(404,"Case not found")
    scan_q=db.query(Scan).join(CaseScan,CaseScan.scan_id==Scan.id).filter(CaseScan.case_id==row.id,Scan.tenant_id==user.tenant_id)
    art_q=db.query(Artifact).join(CaseArtifact,CaseArtifact.artifact_id==Artifact.id).filter(CaseArtifact.case_id==row.id,Artifact.tenant_id==user.tenant_id)
    if not user.is_admin:
        scan_q=scan_q.filter(Scan.owner_user_id==user.id)
        art_q=art_q.filter(Artifact.owner_user_id==user.id)
    scans=scan_q.all()
    arts=art_q.all()
    return {"id":row.id,"title":row.title,"status":row.status,"priority":row.priority,"notes":row.notes,"created_at":row.created_at,
            "scans":[{"id":s.id,"type":s.scan_type,"target":s.target,"verdict":s.verdict,"risk_score":s.risk_score} for s in scans],
            "artifacts":[{"id":a.id,"filename":a.filename,"type":a.artifact_type,"sha256":a.sha256,"size_bytes":a.size_bytes} for a in arts]}

@router.patch("/{case_id}")
def update_case(case_id:int,payload:CaseUpdate,user:User=Depends(current_user),db:Session=Depends(get_session)):
    query=db.query(Case).filter(Case.id == case_id, Case.tenant_id == user.tenant_id)
    if not user.is_admin:
        query=query.filter(Case.owner_user_id == user.id)
    row=query.first()
    if not row: raise HTTPException(404,"Case not found")
    for field in ("title","status","priority","notes"):
        value=getattr(payload,field)
        if value is not None: setattr(row,field,value)
    db.add(AuditEvent(tenant_id=user.tenant_id,action="case.updated",detail=f"case_id={row.id}")); db.commit(); return {"status":"updated","id":row.id}

@router.post("/{case_id}/link-scan/{scan_id}")
def link_scan(case_id:int,scan_id:int,user:User=Depends(current_user),db:Session=Depends(get_session)):
    case_q=db.query(Case).filter(Case.id == case_id, Case.tenant_id == user.tenant_id)
    scan_q=db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == user.tenant_id)
    if not user.is_admin:
        case_q=case_q.filter(Case.owner_user_id == user.id); scan_q=scan_q.filter(Scan.owner_user_id == user.id)
    case=case_q.first(); scan=scan_q.first()
    if not case or not scan: raise HTTPException(404,"Case or scan not found")
    if not db.query(CaseScan).filter_by(case_id=case_id,scan_id=scan_id).first(): db.add(CaseScan(case_id=case_id,scan_id=scan_id))
    db.add(AuditEvent(tenant_id=user.tenant_id,action="case.scan_linked",detail=f"case_id={case_id};scan_id={scan_id}")); db.commit(); return {"status":"linked"}
