from __future__ import annotations

import asyncio
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
import re
import uuid
import secrets

from fastapi import APIRouter, Depends, File, Header, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from phishhunter.config import settings
from phishhunter.db.database import get_session
from phishhunter.deps import current_user
from phishhunter.models import AnalysisJob, Artifact, IOC, Scan, User, UserActivity
from phishhunter.network_artifacts.jobs import JOB_STORE, Job
from phishhunter.network_artifacts.orchestrator import detect_type
from phishhunter.network_artifacts.schema import SUPPORTED_ARTIFACTS, ArtifactInput
from phishhunter.network_artifacts.reporting import csv_events, csv_iocs, json_report, report_html, stix_bundle
from phishhunter.analyzers.pcap.analyzer import _classic_pcap, _pcapng, _packet_fields
from phishhunter.network_artifacts.reporting.pdf import report_pdf
from phishhunter.network_artifacts.toolchain import catalog as tool_catalog, summary as toolchain_summary
from phishhunter.security.csrf import verify_csrf
from phishhunter.security.jwt import decode_token
from phishhunter.security.upload_guard import read_upload_limited, validate_upload

router = APIRouter(prefix="/pcap", tags=["PCAP / Network Artifacts"])

_GUEST_COOKIE = "k4_guest_id"
_GUEST_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


def _artifact_root() -> Path:
    root = Path(settings.storage_dir) / "network-artifacts"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _guest_id(request: Request) -> str:
    value = request.cookies.get(_GUEST_COOKIE, "")
    if not _GUEST_RE.fullmatch(value):
        value = uuid.uuid4().hex
    request.state.network_guest_id = value
    return value


def _optional_user(request: Request, db: Session) -> User | None:
    cookie_token = request.cookies.get("access_token")
    authorization = request.headers.get("Authorization", "")
    bearer_token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    token = cookie_token or bearer_token
    request.state.auth_via_cookie = bool(cookie_token and not bearer_token)
    if not token:
        return None
    try:
        data = decode_token(token, "access")
        user_id = int(data["sub"])
    except (Exception, KeyError, TypeError, ValueError):
        return None
    user = db.get(User, user_id)
    if not user:
        return None
    return user


def _ensure_job_access(request: Request, db: Session, job: Job, access_key: str | None = None) -> User | None:
    user = _optional_user(request, db)
    if job.owner_user_id is not None:
        if not user or user.id != job.owner_user_id:
            raise HTTPException(403, "This investigation belongs to another account")
        return user
    supplied = access_key or request.headers.get("X-Network-Access-Key") or request.query_params.get("access_key")
    if supplied and secrets.compare_digest(str(supplied), str(job.access_key)):
        return None
    guest = request.cookies.get(_GUEST_COOKIE, "")
    if not guest or job.guest_id != guest:
        raise HTTPException(403, "This guest investigation is not available in this session; use the investigation access key returned at upload time")
    return None


def _json_response(request: Request, payload: dict, *, guest: bool = False) -> JSONResponse:
    response = JSONResponse(payload)
    if guest:
        response.set_cookie(
            _GUEST_COOKIE,
            getattr(request.state, "network_guest_id", None) or _guest_id(request),
            httponly=True,
            secure=settings.cookie_secure or request.url.scheme == "https",
            samesite="lax",
            max_age=60 * 60 * 24,
        )
    return response


@router.get("/capabilities")
def capabilities():
    return {
        "service": "pcap-analyst",
        "workspace": "network-artifacts",
        "artifacts": SUPPORTED_ARTIFACTS,
        "pipeline": ["upload", "validate", "queue", "parse", "correlate", "detect", "enrich", "mitre", "timeline", "graph", "report"],
        "analysis": ["PCAP", "PCAPNG", "Zeek", "Suricata", "NetFlow/IPFIX", "Firewall", "Proxy", "DNS", "DHCP", "static_file_analysis", "hashing", "bounded_tcp_reassembly", "passive_file_carving", "HTTP_metadata", "DNS_analysis", "TLS_SNI", "TLS_metadata_fingerprints", "behavioral_detection", "asset_profiling", "cross_artifact_correlation", "MITRE_candidate_mapping", "incident_response", "timeline", "network_graph", "HTML_report", "PDF_report", "JSON", "CSV", "STIX_2.1"],
        "execution": "passive",
        "guest_analysis": True,
        "account_save": True,
        "deep_analysis": True,
        "ir_workbench": ["interactive_attack_graph", "victim_endpoint_profiling", "kill_chain_timeline", "c2_beaconing_analysis", "exfiltration_tracking", "dns_intelligence", "threat_intelligence_dossier", "packet_level_forensics", "incident_response_action_center", "chain_of_custody", "executive_and_forensic_reporting"],
        "file_analysis": ["MD5", "SHA-1", "SHA-256", "SHA-512", "entropy", "ASCII strings", "IOC extraction", "archive listing", "bounded passive carving"],
        "incident_response": ["preparation", "detection_triage", "containment_planning", "evidence_collection", "analysis", "eradication_planning", "recovery_planning", "lessons_learned"],
        "toolchain": toolchain_summary(),
    }


@router.get("/toolchain")
def toolchain(request: Request, db: Session = Depends(get_session)):
    # Catalog and executable detection are read-only. Third-party tools are never
    # launched by this endpoint.
    _optional_user(request, db)
    return {"summary": toolchain_summary(), "tools": tool_catalog()}


@router.get("/toolchain/{tool_name}")
def toolchain_detail(tool_name: str, request: Request, db: Session = Depends(get_session)):
    _optional_user(request, db)
    wanted = tool_name.strip().lower()
    for row in tool_catalog():
        if row["name"].lower() == wanted:
            return row
    raise HTTPException(404, "Tool adapter not found")


@router.post("/upload")
async def upload_artifacts(
    request: Request,
    files: list[UploadFile] = File(...),
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    db: Session = Depends(get_session),
):
    user = _optional_user(request, db)
    if getattr(request.state, "auth_via_cookie", False):
        verify_csrf(request, x_csrf_token or request.headers.get("X-CSRF-Token", ""))
    if not files or len(files) > 32:
        raise HTTPException(400, "Upload between 1 and 32 network artifacts")

    guest = user is None
    guest_id = _guest_id(request) if guest else None
    artifacts: list[ArtifactInput] = []
    blobs: dict[str, bytes] = {}

    for upload in files:
        original_name = upload.filename or "artifact.txt"
        try:
            data = await read_upload_limited(upload, settings.max_upload_mb * 1024 * 1024)
            safe_name = validate_upload(original_name, data, settings.max_upload_mb)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        artifact_id = sha256(safe_name.encode("utf-8") + data[:1024] + len(data).to_bytes(8, "big")).hexdigest()[:24]
        artifact_type = detect_type(safe_name, data)
        artifact = ArtifactInput(artifact_id, safe_name, artifact_type, len(data), sha256(data).hexdigest(), "")
        artifacts.append(artifact)
        blobs[artifact_id] = data

    job = JOB_STORE.create(
        artifacts,
        blobs,
        owner_user_id=user.id if user else None,
        guest_id=guest_id,
    )
    root = _artifact_root() / job.id
    root.mkdir(parents=True, exist_ok=True)
    for artifact in artifacts:
        path = root / artifact.filename
        path.write_bytes(blobs[artifact.artifact_id])
        artifact.path = str(path)

    # The PCAP Analyst uses this API directly. Persist its upload/job metadata
    # here as well so the authenticated user's Dashboard and Workbench can see
    # the investigation without requiring a second "save" operation.
    if user is not None:
        for artifact in artifacts:
            storage_key = str(Path(artifact.path).resolve().relative_to(Path(settings.storage_dir).resolve()))
            db.add(Artifact(
                tenant_id=user.tenant_id, owner_user_id=user.id, job_id=job.id,
                artifact_key=artifact.artifact_id, filename=artifact.filename,
                artifact_type=artifact.artifact_type, sha256=artifact.sha256,
                size_bytes=artifact.size_bytes, storage_path=storage_key,
            ))
        db.add(AnalysisJob(
            job_id=job.id, tenant_id=user.tenant_id, owner_user_id=user.id,
            status="queued", progress=0, message="Queued", result={},
        ))
        db.add(UserActivity(
            user_id=user.id, event_type="analysis", action="artifact.uploaded",
            detail=f"Uploaded {len(artifacts)} network artifact(s) for investigation",
            success=True, metadata_json={"job_id": job.id, "filenames": [a.filename for a in artifacts]},
        ))
        db.commit()

    payload = {
        "job_id": job.id,
        "status": job.status,
        "owner": "account" if user else "guest",
        "access_key": job.access_key if guest else None,
        "artifacts": [asdict(a) for a in artifacts],
    }
    return _json_response(request, payload, guest=guest)


@router.post("/analyze/{job_id}")
async def start_analysis(job_id: str, request: Request, access_key: str | None = None, db: Session = Depends(get_session)):
    try:
        job = JOB_STORE.get(job_id)
    except KeyError as exc:
        raise HTTPException(404, "Job not found") from exc
    _ensure_job_access(request, db, job, access_key)
    if job.status == "running":
        return {"job_id": job.id, "status": job.status, "message": "Analysis already running"}
    if job.status == "completed":
        return {"job_id": job.id, "status": job.status, "message": "Analysis already completed"}
    asyncio.create_task(JOB_STORE.run(job))
    return {"job_id": job.id, "status": "queued", "message": "Analysis queued"}


@router.get("/jobs")
def list_jobs(request: Request, db: Session = Depends(get_session)):
    user = _optional_user(request, db)
    guest = _guest_id(request) if user is None else None
    jobs = []
    for job in list(JOB_STORE.jobs.values())[-100:][::-1]:
        if user and job.owner_user_id == user.id or guest and job.guest_id == guest:
            jobs.append({"job_id": job.id, "status": job.status, "progress": job.progress, "message": job.message, "created_at": job.created_at, "started_at": job.started_at, "completed_at": job.completed_at, "duration_seconds": job.duration_seconds})
    return jobs


@router.get("/jobs/{job_id}")
def job_status(job_id: str, request: Request, access_key: str | None = None, db: Session = Depends(get_session)):
    try:
        job = JOB_STORE.get(job_id)
    except KeyError as exc:
        raise HTTPException(404, "Job not found") from exc
    _ensure_job_access(request, db, job, access_key)
    return {
        "job_id": job.id,
        "status": job.status,
        "progress": job.progress,
        "message": job.message,
        "error": job.error,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "duration_seconds": job.duration_seconds,
        "phase_history": job.phase_history[-100:],
        "access_key": job.access_key if job.owner_user_id is None else None,
        "result": job.result if job.status == "completed" else None,
    }


@router.get("/jobs/{job_id}/packets")
def job_packets(
    job_id: str,
    request: Request,
    offset: int = 0,
    limit: int = 100,
    filter_text: str | None = None,
    access_key: str | None = None,
    db: Session = Depends(get_session),
):
    """Bounded, read-only packet drill-down for the forensic workstation."""
    try:
        job = JOB_STORE.get(job_id)
    except KeyError as exc:
        raise HTTPException(404, "Job not found") from exc
    _ensure_job_access(request, db, job, access_key)
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    wanted = (filter_text or "").strip().lower()
    pcap_artifacts = [a for a in job.artifacts if a.artifact_type == "pcap"]
    rows = []
    total = 0
    for artifact in pcap_artifacts:
        blob = job.blobs.get(artifact.artifact_id, b"")
        try:
            if blob[:4] == b"\x0a\x0d\x0d\x0a":
                _link, _snap, records = _pcapng(blob)
            else:
                _link, _snap, records = _classic_pcap(blob)
        except Exception:
            continue
        for packet_index, (ts, raw) in enumerate(records):
            fields = _packet_fields(raw)
            searchable = " ".join(str(fields.get(k, "")) for k in ("src", "dst", "sport", "dport", "protocol", "tls_sni"))
            if wanted and wanted not in searchable.lower():
                continue
            total += 1
            if total <= offset or len(rows) >= limit:
                continue
            rows.append({
                "artifact_id": artifact.artifact_id,
                "filename": artifact.filename,
                "packet_index": packet_index + 1,
                "timestamp": ts,
                "length": len(raw),
                "src_ip": fields.get("src"), "dst_ip": fields.get("dst"),
                "src_port": fields.get("sport"), "dst_port": fields.get("dport"),
                "protocol": fields.get("protocol"),
                "tcp_flags": fields.get("tcp_flags", {}),
                "dns": fields.get("dns"),
                "http": fields.get("http"),
                "tls_sni": fields.get("tls_sni"),
                "hex_preview": raw[:256].hex(" "),
                "hex_truncated": len(raw) > 256,
            })
            if len(rows) >= limit:
                # We still need total for pagination, so continue counting matches.
                continue
    return {"job_id": job.id, "offset": offset, "limit": limit, "total": total, "packets": rows}


@router.post("/jobs/{job_id}/agent/query")
def agent_query(job_id: str, request: Request, question: str = "", access_key: str | None = None, db: Session = Depends(get_session)):
    """Evidence-grounded analyst assistant. It only searches the completed case result; it never executes commands or uploaded files."""
    job = JOB_STORE.get(job_id)
    _ensure_job_access(request, db, job, access_key)
    if not job.result:
        raise HTTPException(409, "Job is not complete")
    q = (question or "").strip()
    if not q:
        raise HTTPException(400, "Question is required")
    lower = q.lower()
    result = job.result
    events = result.get("events") or []
    candidates=[]
    # Search exact indicators/entities first.
    for e in events:
        blob = " ".join(str(e.get(k,"")) for k in ("src_ip","dst_ip","hostname","protocol","message","event_type")).lower()
        if lower in blob:
            candidates.append(e)
            if len(candidates)>=100: break
    if not candidates:
        for value in (result.get("iocs",{}).get("ips",[]) + result.get("iocs",{}).get("domains",[]))[:2000]:
            if lower in str(value).lower() or str(value).lower() in lower:
                candidates.append({"indicator":value,"source":"ioc-ledger"})
                if len(candidates)>=100: break
    focus = []
    if any(x in lower for x in ("suspicious file","malicious file","file","artifact")):
        focus = result.get("suspicious_file_candidates") or result.get("extracted_files") or []
    elif any(x in lower for x in ("beacon","c2","command and control")):
        focus = result.get("behavioral_analysis",{}).get("beaconing_candidates",[])
    elif any(x in lower for x in ("dns","tunnel","dga")):
        focus = result.get("behavioral_analysis",{}).get("dns_tunneling_candidates",[]) + result.get("behavioral_analysis",{}).get("dga_candidates",[])
    elif any(x in lower for x in ("exfil","stolen","outbound")):
        focus = result.get("behavioral_analysis",{}).get("exfiltration_candidates",[])
    elif any(x in lower for x in ("finding","alert","detect")):
        focus = result.get("findings",[])[:100]
    return {
        "job_id": job.id,
        "question": q,
        "answer": "Evidence-grounded analyst search completed. Results below are observations/candidates, not automatic attribution.",
        "matched_events": candidates,
        "focused_evidence": focus[:100],
        "suggested_pivots":["timeline","network_graph","files","iocs","packet_level_forensics","incident_response"],
        "guardrails":{"payload_execution":False,"active_scanning":False,"unsupported_attribution":False},
    }


@router.get("/jobs/{job_id}/iocs")
def job_iocs(job_id: str, request: Request, kind: str | None = None, access_key: str | None = None, db: Session = Depends(get_session)):
    job = JOB_STORE.get(job_id)
    _ensure_job_access(request, db, job, access_key)
    if not job.result:
        raise HTTPException(409, "Job is not complete")
    iocs = job.result.get("iocs", {})
    return {"job_id": job.id, "iocs": ({kind: iocs.get(kind, [])} if kind else iocs)}


@router.get("/jobs/{job_id}/artifacts")
def job_artifacts(job_id: str, request: Request, access_key: str | None = None, db: Session = Depends(get_session)):
    job = JOB_STORE.get(job_id)
    _ensure_job_access(request, db, job, access_key)
    return {"job_id": job.id, "artifacts": [asdict(a) for a in job.artifacts]}


@router.get("/jobs/{job_id}/report/{fmt}")
def job_report_format(job_id: str, fmt: str, request: Request, access_key: str | None = None, db: Session = Depends(get_session)):
    job = JOB_STORE.get(job_id)
    _ensure_job_access(request, db, job, access_key)
    if not job.result:
        raise HTTPException(409, "Job is not complete")
    generators = {
        "json": (json_report, "application/json", "json"),
        "ioc-csv": (csv_iocs, "text/csv", "iocs.csv"),
        "events-csv": (csv_events, "text/csv", "events.csv"),
        "stix": (stix_bundle, "application/json", "stix.json"),
        "html": (report_html, "text/html", "html"),
        "pdf": (report_pdf, "application/pdf", "pdf"),
    }
    if fmt not in generators:
        raise HTTPException(400, "Unsupported network-artifact report format")
    generator, media, ext = generators[fmt]
    return Response(generator(job.result), media_type=media, headers={"Content-Disposition": f'attachment; filename="network-artifacts-{job.id}.{ext}"'})


@router.get("/jobs/{job_id}/report")
def job_report(job_id: str, request: Request, access_key: str | None = None, db: Session = Depends(get_session)):
    job = JOB_STORE.get(job_id)
    _ensure_job_access(request, db, job, access_key)
    if not job.result:
        raise HTTPException(409, "Job is not complete")
    return {"job_id": job.id, "report": {"title": "Network Artifacts Investigation", "result": job.result, "formats": ["html", "pdf", "json", "ioc-csv", "events-csv", "stix"]}}


@router.post("/jobs/{job_id}/save")
def save_job(
    job_id: str,
    request: Request,
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    if getattr(request.state, "auth_via_cookie", False):
        verify_csrf(request, x_csrf_token or request.headers.get("X-CSRF-Token", ""))
    job = JOB_STORE.get(job_id)
    if job.owner_user_id != user.id:
        raise HTTPException(403, "Only the account that created this investigation can save it")
    if not job.result:
        raise HTTPException(409, "Job is not complete")
    existing = db.query(Scan).filter(Scan.owner_user_id == user.id).order_by(Scan.id.desc()).all()
    for scan in existing:
        metadata = (scan.result or {}).get("case_metadata", {}) if isinstance(scan.result, dict) else {}
        if metadata.get("case_id") == job_id or metadata.get("job_id") == job_id:
            return {"scan_id": scan.id, "job_id": job.id, "already_saved": True}

    filenames = [a.filename for a in job.artifacts]
    scan_result = dict(job.result or {})
    metadata = dict(scan_result.get("case_metadata") or {})
    metadata.update({"case_id": job.id, "job_id": job.id, "source": "network-artifacts", "filenames": filenames})
    scan_result["case_metadata"] = metadata
    scan_result["source_files"] = filenames
    scan = Scan(
        tenant_id=user.tenant_id,
        owner_user_id=user.id,
        scan_type="pcap",
        target=", ".join(filenames)[:10000] or f"network-artifacts:{job_id}",
        status="completed",
        verdict=scan_result.get("verdict", "unknown"),
        risk_score=int(scan_result.get("risk_score", 0) or 0),
        result=scan_result,
    )
    db.add(scan)
    db.flush()
    for kind, values in (scan_result.get("iocs") or {}).items():
        if isinstance(values, list):
            for value in values[:5000]:
                text = str(value).strip()
                if text:
                    db.add(IOC(tenant_id=user.tenant_id, owner_user_id=user.id, kind=str(kind), value=text, source_scan_id=scan.id))
    db.add(UserActivity(
        user_id=user.id, event_type="analysis", action="scan.created",
        detail=f"Saved network investigation scan #{scan.id}", success=True,
        metadata_json={"scan_id": scan.id, "job_id": job.id, "filenames": filenames},
    ))
    db.commit()
    db.refresh(scan)
    return {"scan_id": scan.id, "job_id": job.id, "already_saved": False}


@router.websocket("/ws/{job_id}")
async def job_ws(websocket: WebSocket, job_id: str):
    token = websocket.cookies.get("access_token")
    auth = websocket.headers.get("Authorization", "")
    bearer = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    guest = websocket.cookies.get(_GUEST_COOKIE, "")
    access_key = websocket.query_params.get("access_key") or websocket.headers.get("X-Network-Access-Key")
    user_id = None
    if token or bearer:
        try:
            data = decode_token(token or bearer, "access")
            user_id = int(data["sub"])
        except (Exception, KeyError, TypeError, ValueError):
            await websocket.close(code=1008)
            return
    if not user_id and not _GUEST_RE.fullmatch(guest or ""):
        await websocket.close(code=1008)
        return

    try:
        job = JOB_STORE.get(job_id)
    except KeyError:
        await websocket.accept()
        await websocket.send_json({"error": "Job not found"})
        await websocket.close(code=1008)
        return

    if job.owner_user_id is not None:
        if user_id != job.owner_user_id:
            await websocket.close(code=1008)
            return
    elif not (access_key and secrets.compare_digest(str(access_key), str(job.access_key))) and job.guest_id != guest:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    queue: asyncio.Queue = asyncio.Queue()
    job.subscribers.add(queue)
    try:
        await websocket.send_json({"job_id": job.id, "status": job.status, "progress": job.progress, "message": job.message, "created_at": job.created_at, "started_at": job.started_at, "completed_at": job.completed_at, "duration_seconds": job.duration_seconds})
        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=30)
                await websocket.send_json(message)
                if message.get("status") in {"completed", "failed"}:
                    break
            except asyncio.TimeoutError:
                await websocket.send_json({"job_id": job.id, "status": job.status, "progress": job.progress, "message": job.message, "created_at": job.created_at, "started_at": job.started_at, "completed_at": job.completed_at, "duration_seconds": job.duration_seconds, "heartbeat": True})
    except WebSocketDisconnect:
        pass
    finally:
        job.subscribers.discard(queue)
