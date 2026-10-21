from __future__ import annotations

from fastapi import APIRouter, Depends, File, Header, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from phishhunter.analyzers.email_analyzer import analyze_email
from phishhunter.analyzers.email_deep_engine import analyze_email_deep
from phishhunter.services.email_agent import connector_fabric, agent_manifest
from phishhunter.analyzers.file_analyzer import analyze_file
from phishhunter.analyzers.url_analyzer import analyze_url
from phishhunter.api.schemas import URLRequest
from phishhunter.db.database import get_session
from phishhunter.deps import current_user
from phishhunter.enrichment.registry import connector_catalog
from phishhunter.models import Scan, User
from phishhunter.security.csrf import verify_csrf
from phishhunter.security.upload_guard import read_upload_limited, validate_upload
from phishhunter.enrichment.service import enrich_result
from phishhunter.analysis.graph_builder import build_graph
from phishhunter.version import APP_VERSION
from phishhunter.network_artifacts.api import router as network_artifacts_router

router = APIRouter(prefix="/api/v1", tags=["api"])


@router.get("/health")
def health():
    return {"status": "ok", "service": "phishhunter", "version": APP_VERSION}


@router.get("/enrichment/catalog")
def enrichment_catalog():
    return {"providers": connector_catalog()}


@router.get("/scans")
def scans(user: User = Depends(current_user), db: Session = Depends(get_session)):
    query = db.query(Scan).filter(Scan.tenant_id == user.tenant_id)
    if not user.is_admin:
        query = query.filter(Scan.owner_user_id == user.id)
    return [
        {
            "id": scan.id,
            "type": scan.scan_type,
            "target": scan.target,
            "verdict": scan.verdict,
            "risk_score": scan.risk_score,
            "status": scan.status,
            "created_at": scan.created_at.isoformat(),
        }
        for scan in query.order_by(Scan.id.desc()).limit(100).all()
    ]


@router.post("/url")
async def url_scan(
    request: Request,
    payload: URLRequest,
    x_csrf_token: str | None = Header(default=None),
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    if getattr(request.state, "auth_via_cookie", False):
        verify_csrf(request, x_csrf_token or "")
    result = await analyze_url(payload.url)
    result["enrichment"] = await enrich_result(result, "url")
    scan = Scan(
        tenant_id=user.tenant_id,
        owner_user_id=user.id,
        scan_type="url",
        target=payload.url,
        status="completed",
        verdict=result["verdict"],
        risk_score=result["risk_score"],
        result=result,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return {"scan_id": scan.id, "result": result}


@router.post("/email")
async def email_scan(
    request: Request,
    file: UploadFile = File(...),
    x_csrf_token: str | None = Header(default=None),
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    if getattr(request.state, "auth_via_cookie", False):
        verify_csrf(request, x_csrf_token or "")
    data = await read_upload_limited(file, 25 * 1024 * 1024)
    filename = validate_upload(file.filename or "email.eml", data, 25)
    result = analyze_email_deep(data)
    result["email_fabric"] = connector_fabric()
    result["email_agent_manifest"] = agent_manifest()
    scan = Scan(tenant_id=user.tenant_id, owner_user_id=user.id, scan_type="email", target=filename, status="completed", verdict=result["verdict"], risk_score=result["risk_score"], result=result)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return {"scan_id": scan.id, "result": result}



@router.get("/scans/{scan_id}")
def scan_detail(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_session)):
    scan_query = db.query(Scan).filter(Scan.id == scan_id)
    if not user.is_admin:
        scan_query = scan_query.filter(Scan.owner_user_id == user.id)
    else:
        scan_query = scan_query.filter(Scan.tenant_id == user.tenant_id)
    scan = scan_query.first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {"scan_id": scan.id, "type": scan.scan_type, "target": scan.target, "status": scan.status, "verdict": scan.verdict, "risk_score": scan.risk_score, "result": scan.result}


@router.get("/scans/{scan_id}/graph")
def scan_graph(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_session)):
    scan_query = db.query(Scan).filter(Scan.id == scan_id)
    if not user.is_admin:
        scan_query = scan_query.filter(Scan.owner_user_id == user.id)
    else:
        scan_query = scan_query.filter(Scan.tenant_id == user.tenant_id)
    scan = scan_query.first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return build_graph(scan.result)

@router.post("/file")
async def file_scan(
    request: Request,
    file: UploadFile = File(...),
    x_csrf_token: str | None = Header(default=None),
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    if getattr(request.state, "auth_via_cookie", False):
        verify_csrf(request, x_csrf_token or "")
    data = await read_upload_limited(file, 25 * 1024 * 1024)
    filename = validate_upload(file.filename or "sample.bin", data, 25)
    result = analyze_file(filename, data)
    result["enrichment"] = await enrich_result(result, "file")
    scan = Scan(tenant_id=user.tenant_id, owner_user_id=user.id, scan_type="file", target=filename, status="completed", verdict=result["verdict"], risk_score=result["risk_score"], result=result)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return {"scan_id": scan.id, "result": result}

# PCAP Analyst only: Network Artifacts API siblings (PCAP, Zeek, Suricata, NetFlow/IPFIX, logs).
router.include_router(network_artifacts_router)

# v22 unified architecture routers. These modules share the same SQL tenant boundary
# and are intentionally mounted beside the legacy analyst endpoints so existing URLs keep working.
from phishhunter.api.v1_modules.auth import router as auth_router
from phishhunter.api.v1_modules.users import router as users_router
from phishhunter.api.v1_modules.cases import router as cases_router
from phishhunter.api.v1_modules.artifacts import router as artifacts_router
from phishhunter.api.v1_modules.jobs import router as jobs_router
from phishhunter.api.v1_modules.iocs import router as iocs_router
from phishhunter.api.v1_modules.reports import router as reports_router
from phishhunter.api.v1_modules.health import router as health_router
from phishhunter.api.v1_modules.me import router as me_router

router.include_router(auth_router)
router.include_router(users_router)
router.include_router(cases_router)
router.include_router(artifacts_router)
router.include_router(jobs_router)
router.include_router(iocs_router)
router.include_router(reports_router)
router.include_router(health_router)
router.include_router(me_router)

@router.get("/dashboard/summary", tags=["dashboard"])
def dashboard_summary(user: User = Depends(current_user), db: Session = Depends(get_session)):
    from phishhunter.models import Case, Report, IOC, AuditEvent, Scan, AnalysisJob, Artifact, UserActivity
    if user.is_admin:
        return {
            "scope": "tenant",
            "users": db.query(User).filter_by(tenant_id=user.tenant_id).count(),
            "investigations": db.query(AnalysisJob).filter_by(tenant_id=user.tenant_id).count() + db.query(Scan).filter_by(tenant_id=user.tenant_id).count(),
            "running_jobs": db.query(AnalysisJob).filter(AnalysisJob.tenant_id == user.tenant_id, AnalysisJob.status.in_(["queued", "running"])).count(),
            "high_risk": db.query(Scan).filter(Scan.tenant_id == user.tenant_id, Scan.risk_score >= 70).count(),
            "cases": db.query(Case).filter_by(tenant_id=user.tenant_id).count(),
            "reports": db.query(Report).filter_by(tenant_id=user.tenant_id).count(),
            "iocs": db.query(IOC).filter_by(tenant_id=user.tenant_id).count(),
            "artifacts": db.query(Artifact).filter_by(tenant_id=user.tenant_id).count(),
            "audit_events": db.query(AuditEvent).filter_by(tenant_id=user.tenant_id).count(),
        }
    return {
        "scope": "private",
        "users": 1,
        "investigations": db.query(AnalysisJob).filter(AnalysisJob.owner_user_id == user.id).count() + db.query(Scan).filter(Scan.owner_user_id == user.id).count(),
        "running_jobs": db.query(AnalysisJob).filter(AnalysisJob.owner_user_id == user.id, AnalysisJob.status.in_(["queued", "running"])).count(),
        "high_risk": db.query(Scan).filter(Scan.owner_user_id == user.id, Scan.risk_score >= 70).count(),
        "cases": db.query(Case).filter(Case.owner_user_id == user.id).count(),
        "reports": db.query(Report).filter(Report.owner_user_id == user.id).count(),
        "iocs": db.query(IOC).filter(IOC.owner_user_id == user.id).count(),
        "artifacts": db.query(Artifact).filter(Artifact.owner_user_id == user.id).count(),
        "audit_events": db.query(UserActivity).filter(UserActivity.user_id == user.id).count(),
    }
