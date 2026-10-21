from __future__ import annotations

import os
import secrets
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func

from phishhunter.config import settings
from phishhunter.db.database import SessionLocal, engine
from phishhunter.models import (
    AnalysisJob,
    Artifact,
    AuditEvent,
    Case,
    IOC,
    Report,
    Scan,
    Tenant,
    User,
    UserActivity,
    UserControl,
    UserProfile,
)
from phishhunter.security.jwt import create_access_token, create_refresh_token, decode_token
from phishhunter.security.passwords import hash_password, verify_password

ADMIN_COOKIE = "k4_admin_access"
ADMIN_PREFIX = "/admin"
CSRF_COOKIE = "k4_admin_csrf"
BASE_DIR = Path(__file__).resolve().parent

ALLOWED_VIEWS = {
    "dashboard": "Overview",
    "users": "Users & Access",
    "analytics": "User Analytics",
    "tenants": "Organizations",
    "investigations": "Investigations",
    "cases": "Cases",
    "reports": "Reports",
    "iocs": "IOC Registry",
    "activities": "Audit Center",
    "database": "Database",
    "infrastructure": "Infrastructure",
    "security": "Security",
    "backend": "Backend Architecture",
}

app = FastAPI(title="Phish-Hunter-k4 Administration", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "phishhunter" / "web" / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "admin" / "templates"))


def _admin_base(request: Request) -> str:
    return request.scope.get("root_path") or ADMIN_PREFIX


def _csrf(request: Request) -> str:
    value = request.cookies.get(CSRF_COOKIE)
    if not value:
        value = secrets.token_hex(32)
        request.state.new_csrf = value
    return value


def _admin(request: Request) -> User | None:
    token = request.cookies.get(ADMIN_COOKIE) or request.cookies.get("access_token")
    if not token:
        return None
    try:
        data = decode_token(token, "access")
        uid = int(data["sub"])
    except Exception:
        return None
    with SessionLocal() as db:
        user = db.get(User, uid)
        if not user or not user.is_admin:
            return None
        control = db.query(UserControl).filter_by(user_id=user.id).first()
        if control and control.disabled:
            return None
        return user


def _require(request: Request) -> User:
    user = _admin(request)
    if not user:
        raise HTTPException(401, "Administrator authentication required")
    return user


def _check_csrf(request: Request, csrf: str) -> None:
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if not cookie or not secrets.compare_digest(csrf, cookie):
        raise HTTPException(403, "CSRF validation failed")


def _fmt_dt(value: datetime | None) -> str:
    if not value:
        return "Never"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _activity(
    db,
    *,
    user_id: int | None,
    event_type: str,
    action: str,
    detail: str = "",
    request: Request | None = None,
    actor_user_id: int | None = None,
    success: bool = True,
    metadata: dict | None = None,
) -> None:
    db.add(
        UserActivity(
            user_id=user_id,
            actor_user_id=actor_user_id,
            event_type=event_type,
            action=action,
            detail=detail,
            success=success,
            ip_address=_client_ip(request) if request else "",
            user_agent=(request.headers.get("user-agent", "")[:2000] if request else ""),
            metadata_json=metadata or {},
        )
    )


def _day_key(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).date().isoformat()


def _line_chart(values: list[int], width: int = 560, height: int = 190) -> dict:
    if not values:
        values = [0]
    lo = min(values)
    hi = max(values)
    span = max(hi - lo, 1)
    pad_x, pad_y = 12, 12
    usable_w = width - (pad_x * 2)
    usable_h = height - (pad_y * 2)
    points = []
    for idx, value in enumerate(values):
        x = pad_x + (usable_w * idx / max(len(values) - 1, 1))
        y = pad_y + usable_h - ((value - lo) / span) * usable_h
        points.append(f"{x:.1f},{y:.1f}")
    poly = " ".join(points)
    area = f"{pad_x},{height-pad_y} {poly} {width-pad_x},{height-pad_y}"
    return {"points": poly, "area": area, "min": lo, "max": hi, "last": values[-1], "width": width, "height": height}


def _series(db, days: int = 30, user_id: int | None = None) -> dict:
    now = datetime.now(timezone.utc)
    start_date = (now - timedelta(days=days - 1)).date()
    start = datetime.combine(start_date, datetime.min.time(), tzinfo=timezone.utc)
    query = db.query(UserActivity).filter(UserActivity.created_at >= start)
    if user_id is not None:
        query = query.filter(UserActivity.user_id == user_id)
    rows = query.order_by(UserActivity.created_at.asc()).all()
    dates = [start_date + timedelta(days=i) for i in range(days)]
    keys = [d.isoformat() for d in dates]
    logins = defaultdict(int)
    action_scans = defaultdict(int)
    events = defaultdict(int)
    active = defaultdict(set)
    for row in rows:
        key = _day_key(row.created_at)
        events[key] += 1
        if row.user_id:
            active[key].add(row.user_id)
        if row.action == "login.success":
            logins[key] += 1
        if row.action == "scan.created":
            action_scans[key] += 1

    scan_q = db.query(Scan).filter(Scan.created_at >= start)
    artifact_q = db.query(Artifact).filter(Artifact.created_at >= start)
    report_q = db.query(Report).filter(Report.created_at >= start)
    if user_id is not None:
        scan_q = scan_q.filter(Scan.owner_user_id == user_id)
        artifact_q = artifact_q.filter(Artifact.owner_user_id == user_id)
        report_q = report_q.filter(Report.owner_user_id == user_id)
    scan_rows = scan_q.order_by(Scan.created_at.asc()).all()
    artifact_rows = artifact_q.order_by(Artifact.created_at.asc()).all()
    report_rows = report_q.order_by(Report.created_at.asc()).all()
    scans = defaultdict(int); artifacts = defaultdict(int); reports = defaultdict(int); risk_sum = defaultdict(int); risk_count = defaultdict(int); critical = defaultdict(int)
    for row in scan_rows:
        key = _day_key(row.created_at); scans[key] += 1; score = int(row.risk_score or 0); risk_sum[key] += score; risk_count[key] += 1; critical[key] += 1 if score >= 85 else 0
    for row in artifact_rows: artifacts[_day_key(row.created_at)] += 1
    for row in report_rows: reports[_day_key(row.created_at)] += 1
    labels = [d.strftime("%b %d") for d in dates]
    scan_values = [scans[k] for k in keys]
    return {
        "labels": labels,
        "logins": [logins[k] for k in keys],
        "scans": scan_values,
        "action_scans": [action_scans[k] for k in keys],
        "events": [events[k] for k in keys],
        "active": [len(active[k]) for k in keys],
        "artifacts": [artifacts[k] for k in keys],
        "reports": [reports[k] for k in keys],
        "avg_risk": [round(risk_sum[k] / risk_count[k], 1) if risk_count[k] else 0 for k in keys],
        "critical": [critical[k] for k in keys],
        "login_chart": _line_chart([logins[k] for k in keys]),
        "scan_chart": _line_chart(scan_values),
        "activity_chart": _line_chart([events[k] for k in keys]),
        "active_chart": _line_chart([len(active[k]) for k in keys]),
        "artifact_chart": _line_chart([artifacts[k] for k in keys]),
        "report_chart": _line_chart([reports[k] for k in keys]),
    }


def _user_private_data(db, user_id: int, days: int = 30) -> dict:
    scans = db.query(Scan).filter(Scan.owner_user_id == user_id).order_by(Scan.id.desc()).limit(100).all()
    reports = db.query(Report).filter(Report.owner_user_id == user_id).order_by(Report.id.desc()).limit(100).all()
    artifacts = db.query(Artifact).filter(Artifact.owner_user_id == user_id).order_by(Artifact.id.desc()).limit(100).all()
    cases = db.query(Case).filter(Case.owner_user_id == user_id).order_by(Case.id.desc()).limit(100).all()
    iocs = db.query(IOC).filter(IOC.owner_user_id == user_id).order_by(IOC.id.desc()).limit(200).all()
    activities = db.query(UserActivity).filter(UserActivity.user_id == user_id).order_by(UserActivity.created_at.desc()).limit(250).all()
    graph_nodes = [{"id": f"user:{user_id}", "type": "user", "label": f"User #{user_id}", "detail": {"user_id": user_id}}]
    graph_edges = []
    scan_ids = set()
    for row in scans[:18]:
        nid=f"scan:{row.id}"; scan_ids.add(row.id); graph_nodes.append({"id":nid,"type":"scan","label":str(row.target)[:30],"subtitle":f"{row.scan_type.upper()} · risk {int(row.risk_score or 0)}","detail":{"id":row.id,"target":row.target,"type":row.scan_type,"verdict":row.verdict,"risk_score":int(row.risk_score or 0),"created_at":_fmt_dt(row.created_at)}}); graph_edges.append({"source":f"user:{user_id}","target":nid,"kind":"scan"})
    for row in artifacts[:12]:
        nid=f"artifact:{row.id}"; graph_nodes.append({"id":nid,"type":"artifact","label":str(row.filename)[:30],"subtitle":f"{row.artifact_type} · {int(row.size_bytes or 0)} B","detail":{"id":row.id,"filename":row.filename,"type":row.artifact_type,"sha256":row.sha256,"size_bytes":int(row.size_bytes or 0),"created_at":_fmt_dt(row.created_at)}}); graph_edges.append({"source":f"user:{user_id}","target":nid,"kind":"evidence"})
    for row in reports[:10]:
        nid=f"report:{row.id}"; graph_nodes.append({"id":nid,"type":"report","label":str(row.title)[:30],"subtitle":f"{row.format.upper()} · scan #{row.scan_id}","detail":{"id":row.id,"title":row.title,"format":row.format,"scan_id":row.scan_id,"created_at":_fmt_dt(row.created_at)}}); graph_edges.append({"source":f"user:{user_id}","target":nid,"kind":"report"});
        if row.scan_id in scan_ids: graph_edges.append({"source":f"scan:{row.scan_id}","target":nid,"kind":"reported"})
    for row in cases[:8]:
        nid=f"case:{row.id}"; graph_nodes.append({"id":nid,"type":"case","label":str(row.title)[:30],"subtitle":f"{row.priority.upper()} · {row.status}","detail":{"id":row.id,"title":row.title,"status":row.status,"priority":row.priority,"created_at":_fmt_dt(row.created_at)}}); graph_edges.append({"source":f"user:{user_id}","target":nid,"kind":"case"})
    for row in iocs[:16]:
        nid=f"ioc:{row.id}"; graph_nodes.append({"id":nid,"type":"ioc","label":str(row.value)[:30],"subtitle":str(row.kind).upper(),"detail":{"id":row.id,"kind":row.kind,"value":row.value,"source_scan_id":row.source_scan_id,"created_at":_fmt_dt(row.created_at)}}); graph_edges.append({"source":f"user:{user_id}","target":nid,"kind":"ioc"});
        if row.source_scan_id in scan_ids: graph_edges.append({"source":f"scan:{row.source_scan_id}","target":nid,"kind":"extracted"})
    risk_counts={"critical":0,"high":0,"medium":0,"low":0}
    scan_mix=defaultdict(int)
    for row in scans:
        score=int(row.risk_score or 0)
        key="critical" if score>=85 else "high" if score>=60 else "medium" if score>=30 else "low"
        risk_counts[key]+=1
        scan_mix[str(row.scan_type)]+=1
    return {
        "counts": {"scans": len(scans), "reports": len(reports), "artifacts": len(artifacts), "cases": len(cases), "iocs": len(iocs), "events": len(activities)},
        "scans": scans, "reports": reports, "artifacts": artifacts, "cases": cases, "iocs": iocs, "activities": activities,
        "series": _series(db, days, user_id), "graph": {"nodes": graph_nodes, "edges": graph_edges},
        "high_risk": sorted(scans, key=lambda x:int(x.risk_score or 0), reverse=True)[:8],
        "risk_counts": risk_counts,
        "scan_mix": sorted(scan_mix.items(), key=lambda x:x[1], reverse=True),
    }


def _user_row(db, user: User) -> dict:
    profile = db.query(UserProfile).filter_by(user_id=user.id).first()
    control = db.query(UserControl).filter_by(user_id=user.id).first()
    recent = datetime.now(timezone.utc) - timedelta(days=30)
    login_count = (
        db.query(UserActivity)
        .filter(UserActivity.user_id == user.id, UserActivity.action == "login.success", UserActivity.created_at >= recent)
        .count()
    )
    activity_count = db.query(UserActivity).filter(UserActivity.user_id == user.id, UserActivity.created_at >= recent).count()
    last_activity = db.query(func.max(UserActivity.created_at)).filter(UserActivity.user_id == user.id).scalar()
    return {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "tenant_id": user.tenant_id,
        "admin": bool(user.is_admin),
        "disabled": bool(control and control.disabled),
        "name": profile.display_name if profile and profile.display_name else user.email.split("@")[0],
        "job_title": profile.job_title if profile else "Analyst",
        "created": _fmt_dt(user.created_at),
        "last_login": _fmt_dt(control.last_login_at if control else None),
        "last_activity": _fmt_dt(last_activity),
        "logins_30d": login_count,
        "activity_30d": activity_count,
    }


def _dashboard_data(db, search: str = "") -> dict:
    user_rows = [_user_row(db, user) for user in db.query(User).order_by(User.id.desc()).limit(1000).all()]
    tenants = db.query(Tenant).order_by(Tenant.id.desc()).limit(500).all()
    scans = db.query(Scan).order_by(Scan.id.desc()).limit(300).all()
    cases = db.query(Case).order_by(Case.id.desc()).limit(300).all()
    reports = db.query(Report).order_by(Report.id.desc()).limit(300).all()
    iocs = db.query(IOC).order_by(IOC.id.desc()).limit(500).all()
    audit = db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(500).all()
    jobs = db.query(AnalysisJob).order_by(AnalysisJob.id.desc()).limit(300).all()
    artifacts = db.query(Artifact).order_by(Artifact.id.desc()).limit(300).all()

    if search:
        needle = search.casefold()
        user_rows = [r for r in user_rows if needle in f"{r['id']} {r['email']} {r['name']} {r['job_title']} {r['tenant_id']}".casefold()]
        tenants = [t for t in tenants if needle in f"{t.id} {t.name}".casefold()]
        scans = [s for s in scans if needle in f"{s.id} {s.tenant_id} {s.scan_type} {s.target} {s.status} {s.verdict}".casefold()]
        cases = [c for c in cases if needle in f"{c.id} {c.tenant_id} {c.title} {c.status} {c.priority}".casefold()]
        reports = [r for r in reports if needle in f"{r.id} {r.tenant_id} {r.scan_id} {r.title} {r.format}".casefold()]
        iocs = [i for i in iocs if needle in f"{i.id} {i.tenant_id} {i.kind} {i.value} {i.source_scan_id}".casefold()]
        jobs = [j for j in jobs if needle in f"{j.id} {j.job_id} {j.status} {j.message}".casefold()]
        artifacts = [a for a in artifacts if needle in f"{a.id} {a.job_id} {a.filename} {a.artifact_type} {a.sha256}".casefold()]
        audit = [e for e in audit if needle in f"{e.id} {e.tenant_id} {e.action} {e.detail}".casefold()]

    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    last_30d = now - timedelta(days=30)
    successful_logins_24h = db.query(UserActivity).filter(UserActivity.action == "login.success", UserActivity.created_at >= last_24h).count()
    active_24h = db.query(func.count(func.distinct(UserActivity.user_id))).filter(UserActivity.user_id.isnot(None), UserActivity.created_at >= last_24h).scalar() or 0
    new_users_7d = db.query(User).filter(User.created_at >= last_7d).count()
    disabled = db.query(UserControl).filter(UserControl.disabled.is_(True)).count()
    active_30d = db.query(func.count(func.distinct(UserActivity.user_id))).filter(UserActivity.user_id.isnot(None), UserActivity.created_at >= last_30d).scalar() or 0
    series = _series(db, 30)

    tenant_user_counts = {t.id: db.query(User).filter_by(tenant_id=t.id).count() for t in tenants}
    return {
        "stats": {
            "users": db.query(User).count(),
            "admins": db.query(User).filter_by(is_admin=True).count(),
            "analysts": db.query(User).filter_by(is_admin=False).count(),
            "disabled": disabled,
            "active_30d": active_30d,
            "active_24h": active_24h,
            "logins_24h": successful_logins_24h,
            "new_users_7d": new_users_7d,
            "tenants": db.query(Tenant).count(),
            "scans": db.query(Scan).count(),
            "high": db.query(Scan).filter(Scan.risk_score >= 60).count(),
            "critical": db.query(Scan).filter(Scan.risk_score >= 80).count(),
            "cases": db.query(Case).count(),
            "open_cases": db.query(Case).filter(Case.status == "open").count(),
            "reports": db.query(Report).count(),
            "iocs": db.query(IOC).count(),
            "audit": db.query(AuditEvent).count(),
            "jobs": db.query(AnalysisJob).count(),
            "running_jobs": db.query(AnalysisJob).filter(AnalysisJob.status.in_(["queued", "running"])).count(),
            "artifacts": db.query(Artifact).count(),
            "user_activity": db.query(UserActivity).count(),
        },
        "users": user_rows[:300],
        "tenants": tenants[:200],
        "tenant_user_counts": tenant_user_counts,
        "scans": scans[:200],
        "cases": cases[:200],
        "reports": reports[:200],
        "iocs": iocs[:300],
        "audit": audit[:300],
        "jobs": jobs[:300],
        "artifacts": artifacts[:300],
        "series": series,
        "search": search,
    }


def _render(request: Request, view: str = "dashboard", search: str = "", **extra):
    view = view if view in ALLOWED_VIEWS or view == "user-detail" else "dashboard"
    with SessionLocal() as db:
        data = _dashboard_data(db, search)
        data["storage_size"] = 0
        try:
            db_path = getattr(engine.url, "database", None)
            if db_path and Path(db_path).exists():
                data["storage_size"] = Path(db_path).stat().st_size
        except OSError:
            pass
    db_bytes = data.get("storage_size", 0)
    if db_bytes < 1024:
        db_human = f"{db_bytes} B"
    elif db_bytes < 1024 * 1024:
        db_human = f"{db_bytes / 1024:.1f} KB"
    else:
        db_human = f"{db_bytes / (1024 * 1024):.1f} MB"
    ctx = {
        **data,
        "request": request,
        "admin": _admin(request),
        "csrf": _csrf(request),
        "view": view,
        "views": ALLOWED_VIEWS,
        "admin_prefix": _admin_base(request),
        "main_site_url": "/",
        "python_version": sys.version.split()[0],
        "port": settings.port,
        "public_base_url": settings.public_base_url,
        "db_engine": str(engine.url).split(":", 1)[0].upper(),
        "storage_dir": settings.storage_dir,
        "storage_size_human": db_human,
        "timezone": timezone,
        "settings": settings,
    }
    ctx.update(extra)
    return templates.TemplateResponse(request, "dashboard.html", ctx)


@app.middleware("http")
async def admin_security(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; form-action 'self'; frame-ancestors 'none'"
    )
    if getattr(request.state, "new_csrf", None):
        response.set_cookie(
            CSRF_COOKIE,
            request.state.new_csrf,
            httponly=False,
            samesite="strict",
            secure=settings.cookie_secure,
            max_age=86400,
            path="/",
        )
    return response


@app.get("/", response_class=HTMLResponse)
def home(request: Request, view: str = "dashboard", q: str = ""):
    admin = _admin(request)
    if not admin:
        return RedirectResponse(f"{_admin_base(request)}/login", status_code=303)
    return _render(request, view, q)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = ""):
    if _admin(request):
        return RedirectResponse(f"{_admin_base(request)}/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"request": request, "csrf": _csrf(request), "error": error})


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...), csrf: str = Form(...)):
    _check_csrf(request, csrf)
    normalized = email.strip().lower()
    with SessionLocal() as db:
        user = db.query(User).filter_by(email=normalized).first()
        control = db.query(UserControl).filter_by(user_id=user.id).first() if user else None
        valid = bool(user and verify_password(password, user.password_hash) and user.is_admin)
        if valid and control and control.disabled:
            valid = False
            message = "This administrator account is disabled."
            status = 403
        elif not valid:
            message = "Invalid administrator email or password."
            status = 401
        else:
            message = ""
            status = 200
        if not valid:
            if control:
                control.failed_logins = int(control.failed_logins or 0) + 1
            _activity(db, user_id=user.id if user else None, event_type="authentication", action="login.failed", detail=message, request=request, success=False)
            db.commit()
        else:
            if not control:
                control = UserControl(user_id=user.id)
                db.add(control)
            control.last_login_at = datetime.now(timezone.utc)
            control.failed_logins = 0
            db.add(AuditEvent(tenant_id=user.tenant_id, action="admin.login", detail=f"Administrator {user.id} signed in"))
            _activity(db, user_id=user.id, event_type="authentication", action="login.success", detail="Administrator sign-in", request=request, metadata={"role": "admin"})
            db.commit()
            access = create_access_token(str(user.id))
            refresh = create_refresh_token(str(user.id))
    if status != 200:
        response = templates.TemplateResponse(request, "login.html", {"request": request, "csrf": _csrf(request), "error": message, "email": email.strip()})
        response.status_code = status
        return response
    response = RedirectResponse(f"{_admin_base(request)}/", status_code=303)
    for name, value, max_age in [
        (ADMIN_COOKIE, access, settings.access_token_minutes * 60),
        ("access_token", access, settings.access_token_minutes * 60),
        ("refresh_token", refresh, settings.refresh_token_days * 86400),
    ]:
        response.set_cookie(name, value, httponly=True, samesite="strict", secure=settings.cookie_secure, max_age=max_age, path="/")
    return response


@app.post("/logout")
def logout(request: Request, csrf: str = Form(...)):
    _check_csrf(request, csrf)
    admin = _admin(request)
    if admin:
        with SessionLocal() as db:
            _activity(db, user_id=admin.id, event_type="authentication", action="logout", detail="Administrator signed out", request=request)
            db.commit()
    response = RedirectResponse(f"{_admin_base(request)}/login", status_code=303)
    for name in (ADMIN_COOKIE, "access_token", "refresh_token"):
        response.delete_cookie(name, path="/")
    return response


@app.get("/users/{user_id}", response_class=HTMLResponse)
def user_detail(request: Request, user_id: int):
    _require(request)
    with SessionLocal() as db:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(404, "User not found")
        row = _user_row(db, user)
        profile = db.query(UserProfile).filter_by(user_id=user.id).first()
        control = db.query(UserControl).filter_by(user_id=user.id).first()
        tenant = db.get(Tenant, user.tenant_id)
        user_private = _user_private_data(db, user.id, 30)
        series = user_private["series"]
        history = user_private["activities"]
        admin_actions = db.query(AuditEvent).filter(AuditEvent.detail.like(f"%user {user.id}%")).order_by(AuditEvent.created_at.desc()).limit(80).all()
        tenant_counts = {
            "scans": db.query(Scan).filter_by(tenant_id=user.tenant_id).count(),
            "cases": db.query(Case).filter_by(tenant_id=user.tenant_id).count(),
            "reports": db.query(Report).filter_by(tenant_id=user.tenant_id).count(),
            "iocs": db.query(IOC).filter_by(tenant_id=user.tenant_id).count(),
        }
    return _render(
        request,
        "user-detail",
        selected_user=row,
        selected_profile=profile,
        selected_control=control,
        selected_tenant=tenant,
        user_series=series,
        user_history=history,
        user_admin_actions=admin_actions,
        tenant_counts=tenant_counts,
        selected_private=user_private,
    )


@app.post("/users/create")
def create_user(
    request: Request,
    csrf: str = Form(...),
    email: str = Form(...),
    username: str = Form(""),
    password: str = Form(...),
    tenant_id: int = Form(...),
    display_name: str = Form(""),
    job_title: str = Form("Analyst"),
    role: str = Form("analyst"),
):
    admin = _require(request)
    _check_csrf(request, csrf)
    email = email.strip().lower()
    username = username.strip().lower() or email.split("@", 1)[0]
    role = role.strip().lower()
    if role not in {"admin", "analyst"}:
        raise HTTPException(400, "Invalid role")
    if len(password) < 12:
        raise HTTPException(400, "Password must be at least 12 characters")
    with SessionLocal() as db:
        if db.query(User).filter_by(email=email).first():
            raise HTTPException(409, "Email is already registered")
        if db.query(User).filter(User.username == username).first():
            raise HTTPException(409, "Username is already registered")
        tenant = db.get(Tenant, tenant_id)
        if not tenant:
            raise HTTPException(404, "Organization not found")
        user = User(tenant_id=tenant.id, username=username, email=email, password_hash=hash_password(password), is_admin=role == "admin")
        db.add(user)
        db.flush()
        profile = db.query(UserProfile).filter_by(user_id=user.id).first()
        if not profile:
            db.add(UserProfile(user_id=user.id, display_name=display_name.strip() or email.split("@")[0], job_title=job_title.strip() or ("Administrator" if user.is_admin else "Analyst")))
        control_row = db.query(UserControl).filter_by(user_id=user.id).first()
        if not control_row:
            db.add(UserControl(user_id=user.id))
        db.add(AuditEvent(tenant_id=admin.tenant_id, action="admin.user.create", detail=f"Admin {admin.id} created user {user.id} ({email}) role={role}"))
        _activity(db, user_id=user.id, actor_user_id=admin.id, event_type="account", action="account.created_by_admin", detail=f"Account created by administrator #{admin.id}", request=request, metadata={"role": role, "tenant_id": tenant.id})
        db.commit()
    return RedirectResponse(f"{_admin_base(request)}/?view=users&created=1", status_code=303)


@app.post("/users/{user_id}/toggle")
def toggle_user(request: Request, user_id: int, csrf: str = Form(...)):
    admin = _require(request)
    _check_csrf(request, csrf)
    with SessionLocal() as db:
        target = db.get(User, user_id)
        if not target:
            raise HTTPException(404, "User not found")
        if target.id == admin.id:
            raise HTTPException(400, "You cannot disable your own administrator account")
        control = db.query(UserControl).filter_by(user_id=target.id).first() or UserControl(user_id=target.id)
        if not control.disabled and target.is_admin:
            active_admins = db.query(User).join(UserControl, UserControl.user_id == User.id, isouter=True).filter(User.is_admin.is_(True), (UserControl.disabled.is_(False) | UserControl.id.is_(None))).count()
            if active_admins <= 1:
                raise HTTPException(400, "The last active administrator cannot be disabled")
        control.disabled = not control.disabled
        db.add(control)
        state = "disabled" if control.disabled else "enabled"
        db.add(AuditEvent(tenant_id=admin.tenant_id, action=f"admin.user.{state}", detail=f"Admin {admin.id} set user {target.id} disabled={control.disabled}"))
        _activity(db, user_id=target.id, actor_user_id=admin.id, event_type="account", action=f"account.{state}", detail=f"Account {state} by administrator #{admin.id}", request=request)
        db.commit()
    return RedirectResponse(f"{_admin_base(request)}/?view=users", status_code=303)


@app.post("/users/{user_id}/role")
def role_user(request: Request, user_id: int, csrf: str = Form(...), role: str = Form(...)):
    admin = _require(request)
    _check_csrf(request, csrf)
    role = role.strip().lower()
    if role not in {"admin", "analyst"}:
        raise HTTPException(400, "Invalid role")
    with SessionLocal() as db:
        target = db.get(User, user_id)
        if not target:
            raise HTTPException(404, "User not found")
        if target.id == admin.id and role != "admin":
            raise HTTPException(400, "You cannot remove your own administrator access")
        if target.is_admin and role == "analyst":
            admin_count = db.query(User).filter_by(is_admin=True).count()
            if admin_count <= 1:
                raise HTTPException(400, "At least one administrator must remain")
        target.is_admin = role == "admin"
        profile = db.query(UserProfile).filter_by(user_id=target.id).first()
        if profile and role == "admin" and profile.job_title == "Analyst":
            profile.job_title = "Administrator"
        db.add(AuditEvent(tenant_id=admin.tenant_id, action="admin.user.role", detail=f"Admin {admin.id} changed user {target.id} role={role}"))
        _activity(db, user_id=target.id, actor_user_id=admin.id, event_type="authorization", action="account.role_changed", detail=f"Role changed to {role} by administrator #{admin.id}", request=request, metadata={"role": role})
        db.commit()
    return RedirectResponse(f"{_admin_base(request)}/users/{user_id}", status_code=303)


@app.post("/users/{user_id}/password")
def reset_password(request: Request, user_id: int, csrf: str = Form(...), new_password: str = Form(...), confirm_password: str = Form("")):
    admin = _require(request)
    _check_csrf(request, csrf)
    if len(new_password) < 12:
        raise HTTPException(400, "Password must be at least 12 characters")
    if confirm_password and new_password != confirm_password:
        raise HTTPException(400, "Passwords do not match")
    with SessionLocal() as db:
        target = db.get(User, user_id)
        if not target:
            raise HTTPException(404, "User not found")
        target.password_hash = hash_password(new_password)
        control = db.query(UserControl).filter_by(user_id=target.id).first() or UserControl(user_id=target.id)
        control.failed_logins = 0
        control.disabled = False
        db.add(control)
        db.add(AuditEvent(tenant_id=admin.tenant_id, action="admin.user.password_reset", detail=f"Admin {admin.id} reset password for user {target.id}"))
        _activity(db, user_id=target.id, actor_user_id=admin.id, event_type="security", action="password.reset", detail=f"Password reset by administrator #{admin.id}", request=request)
        db.commit()
    return RedirectResponse(f"{_admin_base(request)}/users/{user_id}", status_code=303)


@app.post("/users/{user_id}/delete")
def delete_user(request: Request, user_id: int, csrf: str = Form(...)):
    admin = _require(request)
    _check_csrf(request, csrf)
    with SessionLocal() as db:
        target = db.get(User, user_id)
        if not target:
            raise HTTPException(404, "User not found")
        if target.id == admin.id:
            raise HTTPException(400, "You cannot delete your own administrator account")
        if target.is_admin and db.query(User).filter_by(is_admin=True).count() <= 1:
            raise HTTPException(400, "The last administrator cannot be deleted")
        email = target.email
        db.add(AuditEvent(tenant_id=admin.tenant_id, action="admin.user.delete", detail=f"Admin {admin.id} permanently deleted user {target.id} ({email})"))
        db.query(Artifact).filter(Artifact.owner_user_id == target.id).update({Artifact.owner_user_id: None}, synchronize_session=False)
        db.query(AnalysisJob).filter(AnalysisJob.owner_user_id == target.id).update({AnalysisJob.owner_user_id: None}, synchronize_session=False)
        db.query(Scan).filter(Scan.owner_user_id == target.id).update({Scan.owner_user_id: None}, synchronize_session=False)
        db.query(Report).filter(Report.owner_user_id == target.id).update({Report.owner_user_id: None}, synchronize_session=False)
        db.query(IOC).filter(IOC.owner_user_id == target.id).update({IOC.owner_user_id: None}, synchronize_session=False)
        db.query(Case).filter(Case.owner_user_id == target.id).update({Case.owner_user_id: None}, synchronize_session=False)
        db.query(UserActivity).filter((UserActivity.user_id == target.id) | (UserActivity.actor_user_id == target.id)).delete(synchronize_session=False)
        db.query(UserProfile).filter_by(user_id=target.id).delete(synchronize_session=False)
        db.query(UserControl).filter_by(user_id=target.id).delete(synchronize_session=False)
        db.delete(target)
        db.commit()
    return RedirectResponse(f"{_admin_base(request)}/?view=users&deleted=1", status_code=303)


@app.post("/users/{user_id}/profile")
def update_profile(request: Request, user_id: int, csrf: str = Form(...), display_name: str = Form(""), job_title: str = Form("Analyst")):
    admin = _require(request)
    _check_csrf(request, csrf)
    with SessionLocal() as db:
        target = db.get(User, user_id)
        if not target:
            raise HTTPException(404, "User not found")
        profile = db.query(UserProfile).filter_by(user_id=user_id).first() or UserProfile(user_id=user_id)
        profile.display_name = display_name.strip()[:120]
        profile.job_title = job_title.strip()[:160] or "Analyst"
        db.add(profile)
        db.add(AuditEvent(tenant_id=admin.tenant_id, action="admin.user.profile", detail=f"Admin {admin.id} updated profile for user {user_id}"))
        _activity(db, user_id=user_id, actor_user_id=admin.id, event_type="account", action="profile.updated", detail=f"Profile updated by administrator #{admin.id}", request=request)
        db.commit()
    return RedirectResponse(f"{_admin_base(request)}/users/{user_id}", status_code=303)


@app.post("/tenants/create")
def create_tenant(request: Request, csrf: str = Form(...), name: str = Form(...)):
    admin = _require(request)
    _check_csrf(request, csrf)
    name = name.strip()
    if not name:
        raise HTTPException(400, "Organization name is required")
    with SessionLocal() as db:
        if db.query(Tenant).filter_by(name=name).first():
            raise HTTPException(409, "Organization already exists")
        tenant = Tenant(name=name)
        db.add(tenant)
        db.flush()
        db.add(AuditEvent(tenant_id=admin.tenant_id, action="admin.tenant.create", detail=f"Admin {admin.id} created organization {tenant.id}"))
        db.commit()
    return RedirectResponse(f"{_admin_base(request)}/?view=tenants&created=1", status_code=303)


@app.post("/tenants/{tenant_id}/delete")
def delete_tenant(request: Request, tenant_id: int, csrf: str = Form(...)):
    admin = _require(request)
    _check_csrf(request, csrf)
    with SessionLocal() as db:
        tenant = db.get(Tenant, tenant_id)
        if not tenant:
            raise HTTPException(404, "Organization not found")
        if db.query(User).filter_by(tenant_id=tenant_id).count():
            raise HTTPException(400, "Organization still has users. Reassign or delete users first.")
        name = tenant.name
        db.delete(tenant)
        db.add(AuditEvent(tenant_id=admin.tenant_id, action="admin.tenant.delete", detail=f"Admin {admin.id} deleted organization {tenant_id} ({name})"))
        db.commit()
    return RedirectResponse(f"{_admin_base(request)}/?view=tenants&deleted=1", status_code=303)


@app.get("/resource/{kind}")
def resource_page(request: Request, kind: str):
    _require(request)
    mapping = {"users": "users", "tenants": "tenants", "scans": "investigations", "cases": "cases", "reports": "reports", "iocs": "iocs", "audit": "activities"}
    if kind not in mapping:
        raise HTTPException(404, "Admin resource not found")
    return RedirectResponse(f"{_admin_base(request)}/?view={mapping[kind]}", status_code=303)


@app.get("/api/summary")
def api_summary(request: Request):
    _require(request)
    with SessionLocal() as db:
        data = _dashboard_data(db)
    return JSONResponse({"stats": data["stats"], "series": data["series"]})


@app.get("/api/analytics")
def api_analytics(request: Request, days: int = 30):
    _require(request)
    days = max(7, min(days, 90))
    with SessionLocal() as db:
        data = _series(db, days)
    return JSONResponse(data)


@app.get("/api/search")
def api_search(request: Request, q: str = ""):
    _require(request)
    with SessionLocal() as db:
        data = _dashboard_data(db, q.strip())
    return JSONResponse({
        "query": q,
        "users": [{"id": u["id"], "email": u["email"], "name": u["name"]} for u in data["users"][:20]],
        "investigations": [{"id": s.id, "target": s.target, "type": s.scan_type, "risk": s.risk_score} for s in data["scans"][:20]],
        "cases": [{"id": c.id, "title": c.title, "status": c.status} for c in data["cases"][:20]],
        "iocs": [{"id": i.id, "kind": i.kind, "value": i.value} for i in data["iocs"][:20]],
    })


@app.get("/health")
def health():
    with SessionLocal() as db:
        return {"status": "ok", "service": "phish-hunter-admin", "port": settings.port, "users": db.query(User).count(), "scans": db.query(Scan).count()}
