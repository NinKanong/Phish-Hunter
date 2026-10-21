from __future__ import annotations
import hashlib, uuid, asyncio
from dataclasses import asdict
from fastapi import APIRouter, Depends, File, Header, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session
from phishhunter.config import settings
from phishhunter.db.database import get_session
from phishhunter.deps import current_user
from phishhunter.models import User, AnalysisJob, Artifact, AuditEvent
from phishhunter.network_artifacts.jobs import JOB_STORE
from phishhunter.network_artifacts.orchestrator import detect_type
from phishhunter.network_artifacts.schema import ArtifactInput
from phishhunter.security.csrf import verify_csrf
from phishhunter.security.upload_guard import read_upload_limited, validate_upload
from phishhunter.services.storage_service import storage_service
from .jobs import _run
router=APIRouter(prefix="/artifacts",tags=["artifacts"])

@router.get("")
def list_artifacts(user:User=Depends(current_user),db:Session=Depends(get_session)):
    query=db.query(Artifact).filter(Artifact.tenant_id == user.tenant_id)
    if not user.is_admin:
        query=query.filter(Artifact.owner_user_id == user.id)
    rows=query.order_by(Artifact.id.desc()).limit(500).all()
    return [{"id":r.id,"job_id":r.job_id,"filename":r.filename,"type":r.artifact_type,"sha256":r.sha256,"size_bytes":r.size_bytes,"created_at":r.created_at} for r in rows]

@router.post("")
async def create_artifacts(request:Request,files:list[UploadFile]=File(...),x_csrf_token:str|None=Header(default=None,alias="X-CSRF-Token"),user:User=Depends(current_user),db:Session=Depends(get_session)):
    if getattr(request.state,"auth_via_cookie",False): verify_csrf(request,x_csrf_token or "")
    if not files or len(files)>32: raise HTTPException(400,"Upload between 1 and 32 artifacts")
    artifacts=[]; blobs={}
    job_id=uuid.uuid4().hex
    for upload in files:
        data=await read_upload_limited(upload,settings.max_upload_mb*1024*1024)
        filename=validate_upload(upload.filename or "artifact.bin",data,settings.max_upload_mb)
        digest=hashlib.sha256(data).hexdigest(); artifact_key=hashlib.sha256((filename+digest).encode()).hexdigest()[:24]
        typ=detect_type(filename,data); storage_key,path=storage_service.put(user.tenant_id,job_id,filename,data)
        inp=ArtifactInput(artifact_key,filename,typ,len(data),digest,path); artifacts.append(inp); blobs[artifact_key]=data
        db.add(Artifact(tenant_id=user.tenant_id,owner_user_id=user.id,job_id=job_id,artifact_key=artifact_key,filename=filename,artifact_type=typ,sha256=digest,size_bytes=len(data),storage_path=storage_key))
    job=JOB_STORE.create(artifacts,blobs,owner_user_id=user.id)
    # Use the DB row key as the canonical id. JobStore id is replaced so WS/API share one identifier.
    if job.id!=job_id:
        # Keep the generated job id from the live store; update persisted artifact rows to match it.
        db.query(Artifact).filter_by(job_id=job_id).update({"job_id":job.id})
        job_id=job.id
    row=AnalysisJob(job_id=job_id,tenant_id=user.tenant_id,owner_user_id=user.id,status="queued",progress=0,message="Queued")
    db.add(row); db.add(AuditEvent(tenant_id=user.tenant_id,action="artifact.uploaded",detail=f"job_id={job_id};count={len(artifacts)}")); db.commit()
    return {"job_id":job_id,"status":"queued","artifacts":[asdict(a) for a in artifacts]}

@router.get("/{artifact_id}")
def artifact_detail(artifact_id:int,user:User=Depends(current_user),db:Session=Depends(get_session)):
    query=db.query(Artifact).filter(Artifact.id == artifact_id, Artifact.tenant_id == user.tenant_id)
    if not user.is_admin:
        query=query.filter(Artifact.owner_user_id == user.id)
    row=query.first()
    if not row: raise HTTPException(404,"Artifact not found")
    return {"id":row.id,"job_id":row.job_id,"filename":row.filename,"type":row.artifact_type,"sha256":row.sha256,"size_bytes":row.size_bytes,"storage_key":row.storage_path,"created_at":row.created_at}
