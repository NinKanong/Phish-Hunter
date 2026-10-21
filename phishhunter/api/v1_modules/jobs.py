from __future__ import annotations
import asyncio, hashlib, secrets
from datetime import datetime, timezone
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from phishhunter.db.database import get_session, SessionLocal
from phishhunter.deps import current_user
from phishhunter.models import User, AnalysisJob, Scan, IOC, Report, AuditEvent
from phishhunter.network_artifacts.jobs import JOB_STORE

router=APIRouter(prefix="/jobs",tags=["jobs"])

def _persist(job_id:str):
    job=JOB_STORE.get(job_id); db=SessionLocal()
    try:
        row=db.query(AnalysisJob).filter_by(job_id=job.id).first()
        if not row: return
        row.status=job.status; row.progress=job.progress; row.message=job.message; row.error=job.error; row.result=job.result or {}
        row.started_at=datetime.fromisoformat(job.started_at) if job.started_at else None
        row.completed_at=datetime.fromisoformat(job.completed_at) if job.completed_at else None
        row.duration_seconds=int(job.duration_seconds or 0)
        if job.status=="completed" and job.result and not row.result.get("_persisted_scan_id"):
            result=job.result
            risk=int(result.get("risk_score", result.get("risk",0)) or 0)
            verdict=str(result.get("verdict", "unknown"))
            scan=Scan(tenant_id=row.tenant_id,owner_user_id=row.owner_user_id,scan_type="network",target=job.id,status="completed",verdict=verdict,risk_score=risk,result=result)
            db.add(scan); db.flush()
            iocs=result.get("iocs") or {}
            if isinstance(iocs,dict):
                for kind,values in iocs.items():
                    if not isinstance(values,list): continue
                    for value in values[:2000]:
                        value=str(value).strip()
                        if value: db.add(IOC(tenant_id=row.tenant_id,owner_user_id=row.owner_user_id,kind=str(kind),value=value,source_scan_id=scan.id))
            report=Report(tenant_id=row.tenant_id,owner_user_id=row.owner_user_id,scan_id=scan.id,title=f"Investigation {job.id[:10]}",format="json",content=__import__('json').dumps(result,indent=2,default=str))
            db.add(report); db.add(AuditEvent(tenant_id=row.tenant_id,action="analysis.completed",detail=f"job_id={job.id};scan_id={scan.id}"))
            result=dict(result); result["_persisted_scan_id"]=scan.id; result["_persisted_report_id"]=report.id; row.result=result
        db.commit()
    finally: db.close()

async def _run(job_id:str):
    await JOB_STORE.run(JOB_STORE.get(job_id)); _persist(job_id)

def _run_sync(job_id: str):
    asyncio.run(_run(job_id))

@router.get("")
def list_jobs(user:User=Depends(current_user),db:Session=Depends(get_session)):
    query=db.query(AnalysisJob).filter(AnalysisJob.tenant_id == user.tenant_id)
    if not user.is_admin:
        query=query.filter(AnalysisJob.owner_user_id == user.id)
    rows=query.order_by(AnalysisJob.id.desc()).limit(200).all()
    return [{"job_id":r.job_id,"status":r.status,"progress":r.progress,"message":r.message,"created_at":r.created_at,"started_at":r.started_at,"completed_at":r.completed_at,"duration_seconds":r.duration_seconds} for r in rows]

@router.get("/{job_id}")
def job_detail(job_id:str,user:User=Depends(current_user),db:Session=Depends(get_session)):
    query=db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id, AnalysisJob.tenant_id == user.tenant_id)
    if not user.is_admin:
        query=query.filter(AnalysisJob.owner_user_id == user.id)
    row=query.first()
    if not row: raise HTTPException(404,"Job not found")
    return {"job_id":row.job_id,"status":row.status,"progress":row.progress,"message":row.message,"error":row.error,"result":row.result if row.status=="completed" else None,"created_at":row.created_at,"started_at":row.started_at,"completed_at":row.completed_at,"duration_seconds":row.duration_seconds}

@router.post("/{job_id}/start")
async def start_job(job_id:str,background_tasks:BackgroundTasks,user:User=Depends(current_user),db:Session=Depends(get_session)):
    query=db.query(AnalysisJob).filter(AnalysisJob.job_id == job_id, AnalysisJob.tenant_id == user.tenant_id)
    if not user.is_admin:
        query=query.filter(AnalysisJob.owner_user_id == user.id)
    row=query.first()
    if not row: raise HTTPException(404,"Job not found")
    if row.status in {"running","completed"}: return {"job_id":job_id,"status":row.status}
    try: JOB_STORE.get(job_id)
    except KeyError: raise HTTPException(409,"Live job data expired; create a new investigation")
    row.status="queued"; db.commit(); background_tasks.add_task(_run_sync, job_id); return {"job_id":job_id,"status":"queued"}

@router.websocket("/ws/{job_id}")
async def job_ws(websocket:WebSocket,job_id:str):
    await websocket.accept()
    try:
        job=JOB_STORE.get(job_id)
    except KeyError:
        await websocket.send_json({"status":"not_found","job_id":job_id}); await websocket.close(); return
    q=asyncio.Queue(); job.subscribers.add(q)
    try:
        await websocket.send_json({"job_id":job.id,"status":job.status,"progress":job.progress,"message":job.message})
        while True: await websocket.send_json(await q.get())
    except WebSocketDisconnect: pass
    finally: job.subscribers.discard(q)
