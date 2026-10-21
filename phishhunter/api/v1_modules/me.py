from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from phishhunter.analysis.graph_builder import build_graph
from phishhunter.db.database import get_session
from phishhunter.deps import current_user
from phishhunter.models import (
    AnalysisJob,
    Artifact,
    Case,
    CaseScan,
    IOC,
    Report,
    Scan,
    User,
    UserActivity,
    UserControl,
    UserProfile,
)

router = APIRouter(prefix="/me", tags=["me"])


def _dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _ioc_count(scan: Scan) -> int:
    data = scan.result if isinstance(scan.result, dict) else {}
    iocs = data.get("iocs") or {}
    return sum(len(v) for v in iocs.values() if isinstance(v, list))


def _scan_access_query(db: Session, user: User):
    """The normal-user boundary is always owner_user_id == authenticated user."""
    return db.query(Scan).filter(Scan.owner_user_id == user.id)


def _day_series(now: datetime, days: int, scans: list[Scan], activity: list[UserActivity], artifacts: list[Artifact], reports: list[Report]) -> list[dict]:
    first = (now - timedelta(days=days - 1)).date()
    scan_days = Counter()
    artifact_days = Counter()
    report_days = Counter()
    login_days = Counter()
    event_days = Counter()
    risk_sum = Counter()
    risk_count = Counter()
    critical_days = Counter()

    for row in scans:
        if row.created_at:
            key = row.created_at.astimezone(timezone.utc).date() if row.created_at.tzinfo else row.created_at.date()
            if key >= first:
                scan_days[key] += 1
                risk_sum[key] += int(row.risk_score or 0)
                risk_count[key] += 1
                if int(row.risk_score or 0) >= 85:
                    critical_days[key] += 1
    for row in artifacts:
        if row.created_at:
            key = row.created_at.astimezone(timezone.utc).date() if row.created_at.tzinfo else row.created_at.date()
            if key >= first:
                artifact_days[key] += 1
    for row in reports:
        if row.created_at:
            key = row.created_at.astimezone(timezone.utc).date() if row.created_at.tzinfo else row.created_at.date()
            if key >= first:
                report_days[key] += 1
    for row in activity:
        if row.created_at:
            key = row.created_at.astimezone(timezone.utc).date() if row.created_at.tzinfo else row.created_at.date()
            if key >= first:
                event_days[key] += 1
                if row.action == "login.success":
                    login_days[key] += 1

    series = []
    for offset in range(days):
        day = first + timedelta(days=offset)
        series.append({
            "date": day.isoformat(),
            "label": day.strftime("%b %d"),
            "short": day.strftime("%d"),
            "weekday": day.strftime("%a"),
            "scans": scan_days[day],
            "logins": login_days[day],
            "events": event_days[day],
            "artifacts": artifact_days[day],
            "reports": report_days[day],
            "critical": critical_days[day],
            "avg_risk": round(risk_sum[day] / risk_count[day], 1) if risk_count[day] else 0,
        })
    return series


def _build_identity_graph(user: User, scans: list[Scan], artifacts: list[Artifact], reports: list[Report], cases: list[Case], iocs: list[IOC]) -> tuple[list[dict], list[dict]]:
    root = f"user:{user.id}"
    nodes: list[dict] = [{
        "id": root,
        "type": "user",
        "label": f"@{user.username or user.email.split('@')[0]}",
        "subtitle": user.email,
        "category": "identity",
        "detail": {"id": user.id, "username": user.username, "email": user.email},
    }]
    edges: list[dict] = []
    scan_ids = set()
    for scan in scans[:18]:
        sid = f"scan:{scan.id}"
        scan_ids.add(scan.id)
        nodes.append({
            "id": sid,
            "type": "scan",
            "label": str(scan.target)[:38],
            "subtitle": f"{scan.scan_type.upper()} · risk {int(scan.risk_score or 0)}",
            "category": "analysis",
            "detail": {
                "id": scan.id,
                "type": scan.scan_type,
                "target": scan.target,
                "verdict": scan.verdict,
                "risk_score": int(scan.risk_score or 0),
                "status": scan.status,
                "created_at": _dt(scan.created_at),
                "ioc_count": _ioc_count(scan),
            },
        })
        edges.append({"source": root, "target": sid, "kind": "created"})
    for artifact in artifacts[:14]:
        aid = f"artifact:{artifact.id}"
        nodes.append({
            "id": aid,
            "type": "artifact",
            "label": str(artifact.filename)[:38],
            "subtitle": f"{artifact.artifact_type} · {int(artifact.size_bytes or 0)} bytes",
            "category": "evidence",
            "detail": {
                "id": artifact.id,
                "filename": artifact.filename,
                "type": artifact.artifact_type,
                "sha256": artifact.sha256,
                "size_bytes": int(artifact.size_bytes or 0),
                "job_id": artifact.job_id,
                "created_at": _dt(artifact.created_at),
            },
        })
        edges.append({"source": root, "target": aid, "kind": "owns"})
    for report in reports[:12]:
        rid = f"report:{report.id}"
        nodes.append({
            "id": rid,
            "type": "report",
            "label": str(report.title)[:38],
            "subtitle": f"{report.format.upper()} · scan #{report.scan_id}",
            "category": "reporting",
            "detail": {"id": report.id, "title": report.title, "format": report.format, "scan_id": report.scan_id, "created_at": _dt(report.created_at)},
        })
        edges.append({"source": root, "target": rid, "kind": "generated"})
        if report.scan_id in scan_ids:
            edges.append({"source": f"scan:{report.scan_id}", "target": rid, "kind": "reported"})
    for case in cases[:10]:
        cid = f"case:{case.id}"
        nodes.append({
            "id": cid,
            "type": "case",
            "label": str(case.title)[:38],
            "subtitle": f"{str(case.priority).upper()} · {case.status}",
            "category": "case",
            "detail": {"id": case.id, "title": case.title, "status": case.status, "priority": case.priority, "created_at": _dt(case.created_at)},
        })
        edges.append({"source": root, "target": cid, "kind": "opened"})
    for ioc in iocs[:18]:
        iid = f"ioc:{ioc.id}"
        nodes.append({
            "id": iid,
            "type": "ioc",
            "label": str(ioc.value)[:38],
            "subtitle": str(ioc.kind).upper(),
            "category": "intelligence",
            "detail": {"id": ioc.id, "kind": ioc.kind, "value": ioc.value, "source_scan_id": ioc.source_scan_id, "created_at": _dt(ioc.created_at)},
        })
        edges.append({"source": root, "target": iid, "kind": "observed"})
        if ioc.source_scan_id in scan_ids:
            edges.append({"source": f"scan:{ioc.source_scan_id}", "target": iid, "kind": "extracted"})
    return nodes, edges


@router.get("/overview")
def overview(
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
    days: int = Query(30, ge=7, le=180, description="Private analytics history window in days"),
):
    profile = db.query(UserProfile).filter_by(user_id=user.id).first()
    control = db.query(UserControl).filter_by(user_id=user.id).first()
    now = datetime.now(timezone.utc)
    window = now - timedelta(days=days)

    scans_all = _scan_access_query(db, user).order_by(Scan.id.desc()).all()
    scans_recent = scans_all[:40]
    scans_window = [s for s in scans_all if s.created_at and (s.created_at.replace(tzinfo=timezone.utc) if s.created_at.tzinfo is None else s.created_at) >= window]
    reports_all = db.query(Report).filter(Report.owner_user_id == user.id).order_by(Report.id.desc()).all()
    reports_recent = reports_all[:30]
    artifacts_all = db.query(Artifact).filter(Artifact.owner_user_id == user.id).order_by(Artifact.id.desc()).all()
    artifacts_recent = artifacts_all[:30]
    jobs_all = db.query(AnalysisJob).filter(AnalysisJob.owner_user_id == user.id).order_by(AnalysisJob.id.desc()).all()
    jobs_recent = jobs_all[:30]
    cases_all = db.query(Case).filter(Case.owner_user_id == user.id).order_by(Case.id.desc()).all()
    cases_recent = cases_all[:30]
    iocs_all = db.query(IOC).filter(IOC.owner_user_id == user.id).order_by(IOC.id.desc()).all()
    iocs_recent = iocs_all[:200]
    activity_all = db.query(UserActivity).filter(UserActivity.user_id == user.id).order_by(UserActivity.created_at.desc()).limit(1000).all()
    activity_window = [a for a in activity_all if a.created_at and (a.created_at.replace(tzinfo=timezone.utc) if a.created_at.tzinfo is None else a.created_at) >= window]

    trend = _day_series(now, days, scans_all, activity_all, artifacts_all, reports_all)
    active_days = sum(1 for point in trend if point["events"] or point["scans"])
    login_days = sum(1 for point in trend if point["logins"])
    total_risk = sum(int(s.risk_score or 0) for s in scans_all)
    avg_risk = round(total_risk / len(scans_all), 1) if scans_all else 0
    highest_risk_scan = max(scans_all, key=lambda s: int(s.risk_score or 0), default=None)
    scan_types: Counter[str] = Counter(str(scan.scan_type) for scan in scans_all)
    verdicts: Counter[str] = Counter(str(scan.verdict or "unknown") for scan in scans_all)
    risk = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for scan in scans_all:
        score = int(scan.risk_score or 0)
        if score >= 85:
            risk["critical"] += 1
        elif score >= 60:
            risk["high"] += 1
        elif score >= 30:
            risk["medium"] += 1
        else:
            risk["low"] += 1

    graph_nodes, graph_edges = _build_identity_graph(user, scans_all, artifacts_all, reports_all, cases_all, iocs_all)

    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "display_name": profile.display_name if profile and profile.display_name else user.username or user.email.split("@")[0],
            "job_title": profile.job_title if profile else ("Administrator" if user.is_admin else "Analyst"),
            "timezone": profile.timezone if profile else "Asia/Phnom_Penh",
            "is_admin": bool(user.is_admin),
            "created_at": _dt(user.created_at),
            "last_login_at": _dt(control.last_login_at if control else None),
            "disabled": bool(control.disabled) if control else False,
        },
        "privacy": {
            "scope": "private",
            "owner_user_id": user.id,
            "message": "This workbench is identity-scoped. Normal accounts receive only rows owned by the authenticated user.",
        },
        "stats": {
            "scans": len(scans_all),
            "scans_30d": len(scans_window),
            "high_risk": risk["high"] + risk["critical"],
            "critical": risk["critical"],
            "reports": len(reports_all),
            "artifacts": len(artifacts_all),
            "jobs": len(jobs_all),
            "cases": len(cases_all),
            "open_cases": sum(1 for c in cases_all if c.status == "open"),
            "iocs": len(iocs_all),
            "events": len(activity_all),
            "events_30d": len(activity_window),
            "active_days_30d": active_days,
            "login_days_30d": login_days,
            "events_window": len(activity_window),
            "active_days_window": active_days,
            "login_days_window": login_days,
            "scans_window": len(scans_window),
            "history_days": days,
            "avg_risk": avg_risk,
            "highest_risk": int(highest_risk_scan.risk_score or 0) if highest_risk_scan else 0,
        },
        "trend": trend,
        "history": {"days": days, "from": trend[0]["date"], "to": trend[-1]["date"]},
        "risk": risk,
        "scan_types": [{"type": key, "count": value} for key, value in scan_types.most_common()],
        "verdicts": [{"verdict": key, "count": value} for key, value in verdicts.most_common()],
        "recent_scans": [
            {
                "id": s.id,
                "type": s.scan_type,
                "target": s.target,
                "status": s.status,
                "verdict": s.verdict,
                "risk_score": int(s.risk_score or 0),
                "ioc_count": _ioc_count(s),
                "created_at": _dt(s.created_at),
            }
            for s in scans_recent
        ],
        "recent_reports": [
            {"id": r.id, "title": r.title, "format": r.format, "scan_id": r.scan_id, "created_at": _dt(r.created_at)}
            for r in reports_recent
        ],
        "recent_artifacts": [
            {"id": a.id, "filename": a.filename, "type": a.artifact_type, "sha256": a.sha256, "size_bytes": int(a.size_bytes or 0), "job_id": a.job_id, "created_at": _dt(a.created_at)}
            for a in artifacts_recent
        ],
        "recent_jobs": [
            {"job_id": j.job_id, "status": j.status, "progress": j.progress, "message": j.message, "created_at": _dt(j.created_at), "completed_at": _dt(j.completed_at), "duration_seconds": j.duration_seconds}
            for j in jobs_recent
        ],
        "recent_cases": [
            {"id": c.id, "title": c.title, "status": c.status, "priority": c.priority, "created_at": _dt(c.created_at)}
            for c in cases_recent
        ],
        "activity": [
            {"id": a.id, "event_type": a.event_type, "action": a.action, "detail": a.detail, "success": bool(a.success), "created_at": _dt(a.created_at), "ip_address": a.ip_address}
            for a in activity_all[:300]
        ],
        "graph": {"nodes": graph_nodes, "edges": graph_edges},
    }


@router.get("/activity")
def activity(user: User = Depends(current_user), db: Session = Depends(get_session)):
    rows = db.query(UserActivity).filter(UserActivity.user_id == user.id).order_by(UserActivity.created_at.desc()).limit(1000).all()
    return [{"id": r.id, "event_type": r.event_type, "action": r.action, "detail": r.detail, "success": bool(r.success), "created_at": _dt(r.created_at)} for r in rows]


@router.get("/scans/{scan_id}")
def scan_detail(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_session)):
    scan = _scan_access_query(db, user).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    reports = db.query(Report).filter(Report.scan_id == scan.id, Report.owner_user_id == user.id).order_by(Report.id.desc()).all()
    iocs = db.query(IOC).filter(IOC.source_scan_id == scan.id, IOC.owner_user_id == user.id).order_by(IOC.id.desc()).all()
    metadata = (scan.result or {}).get("case_metadata", {}) if isinstance(scan.result, dict) else {}
    network_job_id = metadata.get("job_id") or metadata.get("case_id")
    artifact_query = db.query(Artifact).filter(Artifact.owner_user_id == user.id)
    if network_job_id:
        artifacts = artifact_query.filter(Artifact.job_id == str(network_job_id)).order_by(Artifact.id.desc()).all()
    else:
        artifacts = artifact_query.filter(Artifact.job_id == scan.target).order_by(Artifact.id.desc()).all()
    case_links = db.query(Case).join(CaseScan, CaseScan.case_id == Case.id).filter(CaseScan.scan_id == scan.id, Case.owner_user_id == user.id).all()
    return {
        "scan": {"id": scan.id, "type": scan.scan_type, "target": scan.target, "status": scan.status, "verdict": scan.verdict, "risk_score": int(scan.risk_score or 0), "created_at": _dt(scan.created_at), "result": scan.result},
        "iocs": [{"id": x.id, "kind": x.kind, "value": x.value, "created_at": _dt(x.created_at)} for x in iocs],
        "reports": [{"id": x.id, "title": x.title, "format": x.format, "created_at": _dt(x.created_at)} for x in reports],
        "artifacts": [{"id": x.id, "filename": x.filename, "type": x.artifact_type, "sha256": x.sha256, "size_bytes": int(x.size_bytes or 0), "job_id": x.job_id, "created_at": _dt(x.created_at)} for x in artifacts],
        "cases": [{"id": x.id, "title": x.title, "status": x.status, "priority": x.priority, "created_at": _dt(x.created_at)} for x in case_links],
        "graph": build_graph(scan.result if isinstance(scan.result, dict) else {}),
    }
