from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response, PlainTextResponse, FileResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import or_

from phishhunter.analyzers.email_analyzer import analyze_email
from phishhunter.analyzers.file_analyzer import analyze_file
from phishhunter.analyzers.url_analyzer import analyze_url
from phishhunter.analyzers.pcap.analyzer import analyze_pcap
from phishhunter.analysis.graph_builder import build_graph
from phishhunter.enrichment.service import enrich_result
from phishhunter.config import settings
from phishhunter.db.database import get_session, SessionLocal
from phishhunter.deps import current_user
from phishhunter.models import AnalysisJob, Artifact, AuditEvent, Case, ContactMessage, GuestScan, IOC, Report, Scan, Tenant, User, UserControl, UserProfile, UserActivity
from phishhunter.reports import report_html, report_json, report_markdown, report_stix
from phishhunter.security.csrf import signed_report_token, verify_csrf, verify_report_token
from phishhunter.security.jwt import create_access_token, create_refresh_token, decode_token
from phishhunter.security.passwords import hash_password, verify_password
from phishhunter.security.upload_guard import read_upload_limited, validate_upload


templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))
router = APIRouter()


@router.get("/workbench", response_class=HTMLResponse)
def workbench_page(request: Request, user: User = Depends(current_user)):
    index = Path(__file__).resolve().parent / "static" / "workbench" / "index.html"
    if index.exists():
        return FileResponse(
            index,
            media_type="text/html",
            headers={"Cache-Control": "no-store, no-cache, max-age=0", "Pragma": "no-cache"},
        )
    return _render(request, "error.html", error="Workbench frontend is not built. Run: npm --prefix frontend/app install && npm --prefix frontend/app run build")


def _cookie_secure(request: Request) -> bool:
    return settings.cookie_secure or request.url.scheme == "https"


def _render(request: Request, name: str, **context):
    context.setdefault("csrf_token", getattr(request.state, "csrf_token", ""))
    if "services" not in context:
        try:
            from phishhunter.web.services import SERVICE_CATALOG
            context["services"] = SERVICE_CATALOG
        except ImportError:
            context["services"] = {}
    # Navigation is account-aware on every page without forcing authentication.
    if "user" not in context:
        user = None
        token = request.cookies.get("access_token")
        if token:
            try:
                payload = decode_token(token, "access")
                db = SessionLocal()
                try:
                    user = db.get(User, int(payload["sub"]))
                    if user:
                        control = db.query(UserControl).filter_by(user_id=user.id).first()
                        if control and control.disabled:
                            user = None
                finally:
                    db.close()
            except (Exception, KeyError, TypeError, ValueError):
                user = None
        context["user"] = user
    current = context.get("user")
    if current is not None:
        db = SessionLocal()
        try:
            profile = db.query(UserProfile).filter_by(user_id=current.id).first()
            if not profile:
                profile = UserProfile(user_id=current.id, display_name=current.email.split("@")[0])
                db.add(profile); db.commit(); db.refresh(profile)
            context.setdefault("profile", profile)
        finally:
            db.close()
    context.setdefault("authenticated", bool(current))
    context.setdefault("admin_site_url", "/admin")
    return templates.TemplateResponse(request, name, {"request": request, **context})


def _error_response(request: Request, message: str, status_code: int = 400) -> HTMLResponse:
    response = _render(request, "error.html", error=message)
    response.status_code = status_code
    return response


def _record_user_activity(
    db: Session,
    *,
    user_id: int | None,
    event_type: str,
    action: str,
    detail: str = "",
    request: Request | None = None,
    success: bool = True,
    actor_user_id: int | None = None,
    metadata: dict | None = None,
) -> None:
    """Write a durable, non-secret identity activity record."""
    db.add(UserActivity(
        user_id=user_id,
        actor_user_id=actor_user_id,
        event_type=event_type,
        action=action,
        detail=detail,
        success=success,
        ip_address=(request.client.host if request and request.client else ""),
        user_agent=(request.headers.get("user-agent", "")[:2000] if request else ""),
        metadata_json=metadata or {},
    ))


def save_scan(db: Session, user: User, scan_type: str, target: str, result: dict) -> Scan:
    scan = Scan(
        tenant_id=user.tenant_id,
        owner_user_id=user.id,
        scan_type=scan_type,
        target=target,
        status="completed",
        verdict=result.get("verdict", "unknown"),
        risk_score=int(result.get("risk_score", 0)),
        result=result,
    )
    db.add(scan)
    db.flush()
    for kind, values in result.get("iocs", {}).items():
        if not isinstance(values, list):
            continue
        for value in values:
            text_value = str(value).strip()
            if text_value:
                db.add(IOC(tenant_id=user.tenant_id, owner_user_id=user.id, kind=kind, value=text_value, source_scan_id=scan.id))
    _record_user_activity(
        db, user_id=user.id, event_type="analysis", action="scan.created",
        detail=f"Created {scan_type} scan #{scan.id}", metadata={"scan_id": scan.id, "risk_score": scan.risk_score},
    )
    db.commit()
    db.refresh(scan)
    return scan


@router.get("/", response_class=HTMLResponse)
def landing(request: Request):
    return _render(request, "landing.html")


@router.get("/search", response_class=HTMLResponse)
def search_page(request: Request, q: str = ""):
    return _render(request, "docs.html", title="Search", page_title="Search", query=q)


PUBLIC_PAGES = {
    "/product": ("Product", "product.html"),
    "/product/url": ("URL Scanner", "product_url.html"),
    "/product/email": ("Email Analyzer", "product_email.html"),
    "/product/file": ("File Analyzer", "product_file.html"),
    "/product/pcap": ("PCAP Forensics", "product_pcap.html"),
    "/product/sandbox": ("Sandbox Orchestration", "product_sandbox.html"),
    "/product/threat-intel": ("Threat Intelligence", "product_threat_intel.html"),
    "/solutions/soc": ("SOC Teams", "solution_soc.html"),
    "/solutions/mssp": ("MSSP", "solution_mssp.html"),
    "/solutions/ir": ("Incident Response", "solution_ir.html"),
    "/solutions/research": ("Research", "solution_research.html"),
    "/solutions/education": ("Education", "solution_education.html"),
    "/solutions/government": ("Government", "solution_government.html"),
    "/solutions/enterprise": ("Enterprise", "solution_enterprise.html"),
    "/pricing": ("Pricing", "pricing.html"), "/docs": ("Documentation", "docs.html"),
    "/docs/getting-started": ("Getting Started", "docs_getting_started.html"),
    "/docs/api": ("API Reference", "docs_api.html"), "/docs/sdk": ("SDK", "docs_sdk.html"),
    "/docs/integrations": ("Integrations", "docs_integrations.html"),
    "/docs/connectors": ("Connectors", "docs_connectors.html"),
    "/docs/sandbox": ("Sandbox", "docs_sandbox.html"),
    "/docs/pcap": ("PCAP Forensics", "docs_pcap.html"),
    "/docs/yara": ("YARA", "docs_yara.html"), "/docs/playbooks": ("Playbooks", "docs_playbooks.html"),
    "/docs/faq": ("FAQ", "docs_faq.html"), "/blog": ("Blog", "blog.html"),
    "/changelog": ("Changelog", "changelog.html"), "/security": ("Security", "security.html"),
    "/security/bug-bounty": ("Bug Bounty", "bug_bounty.html"), "/about": ("About", "about.html"),
    "/careers": ("Careers", "careers.html"), "/press": ("Press", "press.html"),
    "/contact": ("Contact", "contact.html"), "/partners": ("Partners", "partners.html"),
    "/legal/terms": ("Terms", "terms.html"), "/legal/privacy": ("Privacy", "privacy.html"),
    "/legal/cookies": ("Cookies", "legal_page.html"), "/legal/gdpr": ("GDPR", "legal_page.html"),
    "/legal/dpa": ("DPA", "legal_page.html"), "/legal/sub-processors": ("Sub-processors", "legal_page.html"),
    "/legal/sla": ("SLA", "legal_page.html"), "/accessibility": ("Accessibility", "accessibility.html"),
    "/community": ("Community", "contact.html"), "/support": ("Support Center", "contact.html"),
    "/support/bug": ("Report a Bug", "contact.html"), "/support/feature": ("Feature Request", "contact.html"),
}

for _path, (_title, _template) in PUBLIC_PAGES.items():
    def _make_page(path=_path, title=_title, template=_template):
        @router.get(path, response_class=HTMLResponse)
        def _page(request: Request):
            return _render(request, template, title=title, page_title=title)
        return _page
    _make_page()

@router.post("/contact", response_class=HTMLResponse)
def contact_submit(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    topic: str = Form("General"),
    message: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_session),
):
    verify_csrf(request, csrf_token)
    name = name.strip()[:120]
    email = email.strip().lower()[:320]
    topic = topic.strip()[:80] or "General"
    message = message.strip()[:12000]
    if not name or "@" not in email or not message:
        return _render(request, "contact.html", title="Contact", page_title="Contact", error="Please provide your name, a valid email address, and a message.")
    db.add(ContactMessage(name=name, email=email, topic=topic, message=message, status="new"))
    db.commit()
    return _render(request, "contact.html", title="Contact", page_title="Contact", success="Your message has been saved. Thank you — K4N0NG can review it from the platform inbox.")

@router.get("/sitemap.xml")
def sitemap_xml():
    urls = ["/", *PUBLIC_PAGES.keys(), "/login", "/register", "/status"]
    body = "".join(f"<url><loc>{settings.public_base_url.rstrip('/')}{u}</loc></url>" for u in urls)
    return Response(f"<?xml version=\"1.0\" encoding=\"UTF-8\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">{body}</urlset>", media_type="application/xml")

@router.get("/robots.txt", response_class=PlainTextResponse)
def robots():
    return f"User-agent: *\nAllow: /\nSitemap: {settings.public_base_url.rstrip('/')}/sitemap.xml\n"

APP_ALIASES = {
    "/app/dashboard": "/dashboard", "/app/scans": "/dashboard", "/app/scan/new": "/analyze/url",
    "/app/reports": "/reports", "/app/iocs": "/iocs", "/app/cases": "/cases",
    "/app/pcap": "/analyze/pcap", "/app/settings": "/settings",
    "/app/sandbox": "/status", "/app/integrations": "/docs/integrations",
    "/app/team": "/settings", "/app/apikeys": "/docs/api", "/app/webhooks": "/docs/api",
    "/app/billing": "/pricing", "/app/admin": "/admin",
}
for _app_path, _target in APP_ALIASES.items():
    def _make_alias(path=_app_path, target=_target):
        @router.get(path)
        def _alias():
            return RedirectResponse(target, status_code=307)
        return _alias
    _make_alias()

AUTH_INFO_PAGES = {
    "/forgot-password": "forgot.html", "/reset-password": "reset.html",
    "/verify-email": "verify_email.html", "/mfa": "mfa.html", "/accept-invite": "accept_invite.html",
}
for _auth_path, _auth_template in AUTH_INFO_PAGES.items():
    def _make_auth_page(path=_auth_path, template=_auth_template):
        @router.get(path, response_class=HTMLResponse)
        def _auth_page(request: Request):
            return _render(request, template, user=None, title=path.strip('/').replace('-', ' ').title())
        return _auth_page
    _make_auth_page()

@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return _render(request, "register.html")


def _registration_error(request: Request, message: str, *, username: str = "", email: str = "", status_code: int = 400):
    response = _render(request, "register.html", error=message, username=username, email=email)
    response.status_code = status_code
    return response


def _self_signup_tenant(db: Session) -> Tenant:
    admin_user = db.query(User).filter(User.is_admin.is_(True)).order_by(User.id.asc()).first()
    if admin_user:
        tenant = db.get(Tenant, admin_user.tenant_id)
        if tenant:
            return tenant
    tenant = db.query(Tenant).filter_by(name="Phish-Hunter-k4").first()
    if not tenant:
        tenant = Tenant(name="Phish-Hunter-k4")
        db.add(tenant)
        db.flush()
    return tenant


@router.post("/register")
def register(
    request: Request,
    username: str = Form(""),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(""),
    agree_terms: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_session),
):
    verify_csrf(request, csrf_token)
    email = email.strip().lower()
    username = username.strip().lower() or (email.split("@", 1)[0] if "@" in email else "")
    username_ok = bool(username) and all(ch.isalnum() or ch in "._-" for ch in username) and 3 <= len(username) <= 64
    if len(email) > 320 or len(password) > 256 or len(password) < 12 or not username_ok:
        return _registration_error(request, "Use a valid username and email, and a password of at least 12 characters.", username=username, email=email)
    if not email or "@" not in email:
        return _registration_error(request, "A valid work email is required.", username=username, email=email)
    if confirm_password != password:
        return _registration_error(request, "Passwords do not match.", username=username, email=email)
    if agree_terms not in {"on", "true", "1", "yes"}:
        return _registration_error(request, "You must agree to the terms.", username=username, email=email)
    if db.query(User).filter_by(email=email).first():
        return _registration_error(request, "This email is already registered. Sign in instead.", username=username, email=email, status_code=409)
    if db.query(User).filter(User.username == username).first():
        return _registration_error(request, "This username is already in use. Choose another username.", username=username, email=email, status_code=409)
    tenant = _self_signup_tenant(db)
    user = User(tenant_id=tenant.id, username=username, email=email, password_hash=hash_password(password), is_admin=False)
    db.add(user)
    db.flush()
    profile = db.query(UserProfile).filter_by(user_id=user.id).first()
    if profile:
        profile.display_name = username
        profile.job_title = "Analyst"
        db.add(profile)
    else:
        db.add(UserProfile(user_id=user.id, display_name=username, job_title="Analyst"))
    control = db.query(UserControl).filter_by(user_id=user.id).first()
    if control:
        control.disabled = False
        control.failed_logins = 0
        db.add(control)
    else:
        db.add(UserControl(user_id=user.id))
    _record_user_activity(
        db, user_id=user.id, event_type="account", action="account.created",
        detail=f"Account created for @{username}", request=request, metadata={"username": username},
    )

    guest_id = request.cookies.get("k4_guest_id")
    if guest_id:
        guest_rows = db.query(GuestScan).filter(GuestScan.guest_id == guest_id).order_by(GuestScan.id.asc()).all()
        for guest in guest_rows:
            scan = Scan(tenant_id=tenant.id, owner_user_id=user.id, scan_type=guest.scan_type, target=guest.target,
                        status="completed", verdict=guest.verdict, risk_score=guest.risk_score, result=guest.result)
            db.add(scan)
            db.flush()
            for kind, values in (guest.result.get("iocs", {}) or {}).items():
                if isinstance(values, list):
                    for value in values:
                        value = str(value).strip()
                        if value:
                            db.add(IOC(tenant_id=tenant.id, owner_user_id=user.id, kind=kind, value=value, source_scan_id=scan.id))
            db.delete(guest)
    db.commit()
    response = RedirectResponse("/login?created=1", status_code=303)
    response.delete_cookie("k4_guest_id", path="/")
    return response


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return _render(request, "login.html")


@router.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_session),
):
    verify_csrf(request, csrf_token)
    login_identity = email.strip().lower()
    user = db.query(User).filter(or_(User.email == login_identity, User.username == login_identity)).first()
    control = db.query(UserControl).filter_by(user_id=user.id).first() if user else None
    if not user or not verify_password(password, user.password_hash):
        if control:
            control.failed_logins = int(control.failed_logins or 0) + 1
        _record_user_activity(
            db, user_id=user.id if user else None, event_type="authentication", action="login.failed",
            detail="Invalid email/username or password", request=request, success=False,
        )
        db.commit()
        # Keep the browser on the normal login screen instead of exposing a raw
        # JSON 401 page. This is the same identity endpoint used by admins and
        # analysts; authorization is determined from the SQL user record.
        return _render(
            request,
            "login.html",
            error="Invalid email/username or password.",
            email=email.strip(),
            status_code=401,
        )
    if control and control.disabled:
        raise HTTPException(403, "This account is disabled. Contact your administrator.")
    if not control:
        control = UserControl(user_id=user.id)
        db.add(control)
    control.last_login_at = datetime.now(timezone.utc)
    control.failed_logins = 0
    db.add(AuditEvent(tenant_id=user.tenant_id, action="login", detail=f"User {user.id} signed in"))
    _record_user_activity(
        db, user_id=user.id, event_type="authentication", action="login.success",
        detail="Successful sign-in", request=request, metadata={"role": "admin" if user.is_admin else "analyst"},
    )
    db.commit()
    response = RedirectResponse("/", status_code=303)
    secure = _cookie_secure(request)
    response.set_cookie(
        "access_token",
        create_access_token(str(user.id)),
        httponly=True,
        samesite="strict",
        secure=secure,
        max_age=settings.access_token_minutes * 60,
        path="/",
    )
    response.set_cookie(
        "refresh_token",
        create_refresh_token(str(user.id)),
        httponly=True,
        samesite="strict",
        secure=secure,
        max_age=settings.refresh_token_days * 86400,
        path="/",
    )
    return response


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    verify_csrf(request, csrf_token)
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    # Admin and analyst surfaces share one identity session on the same host.
    response.delete_cookie("k4_admin_access", path="/")
    return response


@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_session)):
    profile = db.query(UserProfile).filter_by(user_id=user.id).first()
    if not profile:
        profile = UserProfile(user_id=user.id, display_name=user.email.split("@")[0])
        db.add(profile); db.commit(); db.refresh(profile)
    scans = db.query(Scan).filter(Scan.owner_user_id == user.id).count()
    reports = db.query(Report).filter(Report.owner_user_id == user.id).count()
    iocs = db.query(IOC).filter(IOC.owner_user_id == user.id).count()
    audit_events = db.query(UserActivity).filter(UserActivity.user_id == user.id).count()
    control = db.query(UserControl).filter_by(user_id=user.id).first()
    return _render(request, "account.html", user=user, profile=profile, title="Account",
                   account_stats={"scans": scans, "reports": reports, "iocs": iocs, "audit": audit_events},
                   last_login=control.last_login_at if control else None)


@router.post("/account", response_class=HTMLResponse)
def account_update(
    request: Request,
    display_name: str = Form(""),
    job_title: str = Form("Analyst"),
    avatar_url: str = Form(""),
    timezone: str = Form("Asia/Phnom_Penh"),
    avatar: UploadFile | None = File(None),
    csrf_token: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    verify_csrf(request, csrf_token)
    profile = db.query(UserProfile).filter_by(user_id=user.id).first()
    if not profile:
        profile = UserProfile(user_id=user.id)
        db.add(profile)
    profile.display_name = display_name.strip()[:120] or user.email.split("@")[0]
    profile.job_title = job_title.strip()[:160] or "Analyst"
    profile.timezone = timezone.strip()[:64] or "Asia/Phnom_Penh"
    if avatar_url.strip():
        profile.avatar_url = avatar_url.strip()[:500]
    if avatar and avatar.filename:
        allowed = {"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp", "image/gif": ".gif"}
        if avatar.content_type not in allowed:
            raise HTTPException(400, "Profile photo must be PNG, JPG, WEBP or GIF.")
        data = avatar.file.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise HTTPException(413, "Profile photo must be 2 MB or smaller.")
        upload_dir = Path(__file__).resolve().parent / "static" / "uploads" / "avatars"
        upload_dir.mkdir(parents=True, exist_ok=True)
        filename = f"user-{user.id}-{uuid.uuid4().hex}{allowed[avatar.content_type]}"
        (upload_dir / filename).write_bytes(data)
        profile.avatar_url = f"/static/uploads/avatars/{filename}"
    db.add(AuditEvent(tenant_id=user.tenant_id, action="profile.updated", detail=f"User {user.id} updated account profile"))
    db.commit()
    return RedirectResponse("/account?saved=1", status_code=303)


@router.get("/team", response_class=HTMLResponse)
def team_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_session)):
    members = []
    profiles = {p.user_id: p for p in db.query(UserProfile).all()}
    controls = {c.user_id: c for c in db.query(UserControl).all()}
    for member in db.query(User).filter_by(tenant_id=user.tenant_id).order_by(User.id.asc()).all():
        profile = profiles.get(member.id)
        control = controls.get(member.id)
        members.append({
            "email": member.email,
            "name": profile.display_name if profile else member.email.split("@")[0],
            "role": "Administrator" if member.is_admin else "Analyst",
            "status": "Disabled" if control and control.disabled else "Active",
            "last_login": control.last_login_at.isoformat() if control and control.last_login_at else "Never",
        })
    return _render(request, "team.html", user=user, members=members, title="Team")


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: User = Depends(current_user), db: Session = Depends(get_session)):
    """Private analyst dashboard: every object is filtered by the authenticated owner id."""
    scans_all = db.query(Scan).filter(Scan.owner_user_id == user.id).order_by(Scan.id.desc()).all()
    reports_all = db.query(Report).filter(Report.owner_user_id == user.id).order_by(Report.id.desc()).all()
    artifacts_all = db.query(Artifact).filter(Artifact.owner_user_id == user.id).order_by(Artifact.id.desc()).all()
    jobs_all = db.query(AnalysisJob).filter(AnalysisJob.owner_user_id == user.id).order_by(AnalysisJob.id.desc()).all()
    cases_all = db.query(Case).filter(Case.owner_user_id == user.id).order_by(Case.id.desc()).all()
    activities_all = db.query(UserActivity).filter(UserActivity.user_id == user.id).order_by(UserActivity.created_at.desc()).limit(1000).all()
    controls = db.query(UserControl).filter_by(user_id=user.id).first()
    profile = db.query(UserProfile).filter_by(user_id=user.id).first()
    now = datetime.now(timezone.utc)
    window = now - timedelta(days=30)

    scans_window = [s for s in scans_all if s.created_at and (s.created_at.replace(tzinfo=timezone.utc) if s.created_at.tzinfo is None else s.created_at) >= window]
    reports_window = [r for r in reports_all if r.created_at and (r.created_at.replace(tzinfo=timezone.utc) if r.created_at.tzinfo is None else r.created_at) >= window]
    artifacts_window = [a for a in artifacts_all if a.created_at and (a.created_at.replace(tzinfo=timezone.utc) if a.created_at.tzinfo is None else a.created_at) >= window]
    activity_window = [a for a in activities_all if a.created_at and (a.created_at.replace(tzinfo=timezone.utc) if a.created_at.tzinfo is None else a.created_at) >= window]

    first = (now - timedelta(days=29)).date()
    activity = []
    for offset in range(30):
        day = first + timedelta(days=offset)
        start_day = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
        end_day = start_day + timedelta(days=1)
        day_scans = [x for x in scans_window if x.created_at and start_day <= (x.created_at.replace(tzinfo=timezone.utc) if x.created_at.tzinfo is None else x.created_at) < end_day]
        day_events = [x for x in activity_window if x.created_at and start_day <= (x.created_at.replace(tzinfo=timezone.utc) if x.created_at.tzinfo is None else x.created_at) < end_day]
        day_artifacts = [x for x in artifacts_window if x.created_at and start_day <= (x.created_at.replace(tzinfo=timezone.utc) if x.created_at.tzinfo is None else x.created_at) < end_day]
        activity.append({
            "label": day.strftime("%b %d"), "short": day.strftime("%d"),
            "scans": len(day_scans),
            "logins": sum(1 for x in day_events if x.action == "login.success"),
            "events": len(day_events),
            "artifacts": len(day_artifacts),
        })

    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    scan_mix = {}
    verdicts = {}
    for scan in scans_all:
        score = int(scan.risk_score or 0)
        key = "critical" if score >= 85 else "high" if score >= 60 else "medium" if score >= 30 else "low"
        risk_counts[key] += 1
        scan_mix[scan.scan_type] = scan_mix.get(scan.scan_type, 0) + 1
        verdict = str(scan.verdict or "unknown")
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
    avg_risk = round(sum(int(x.risk_score or 0) for x in scans_all) / len(scans_all), 1) if scans_all else 0
    high_risk_recent = sorted(scans_window, key=lambda x: int(x.risk_score or 0), reverse=True)[:6]
    open_cases = sum(1 for x in cases_all if x.status == "open")
    active_days = sum(1 for x in activity if x["events"] or x["scans"])
    return _render(
        request, "dashboard.html", user=user, profile=profile, control=controls,
        scans=scans_all[:25], reports=reports_all[:20], artifacts=artifacts_all[:20], jobs=jobs_all[:15], cases=cases_all[:15],
        activities=activities_all[:20], counts={
            "total": len(scans_all), "scans_30d": len(scans_window), "reports": len(reports_all), "reports_30d": len(reports_window),
            "artifacts": len(artifacts_all), "artifacts_30d": len(artifacts_window), "jobs": len(jobs_all), "cases": len(cases_all),
            "open_cases": open_cases, "iocs": db.query(IOC).filter(IOC.owner_user_id == user.id).count(), "events": len(activities_all),
            "events_30d": len(activity_window), "active_days": active_days,
        },
        cases_open=open_cases, audit_count=len(activities_all), activity=activity, risk_counts=risk_counts,
        avg_risk=avg_risk, latest_scan=scans_all[0].created_at if scans_all else None,
        latest_report=reports_all[0] if reports_all else None, latest_artifact=artifacts_all[0] if artifacts_all else None,
        high_risk_recent=high_risk_recent, scan_mix=sorted(scan_mix.items(), key=lambda x: x[1], reverse=True),
        verdicts=sorted(verdicts.items(), key=lambda x: x[1], reverse=True), privacy_scope="private", title="My Dashboard"
    )


@router.get("/analyze/url", response_class=HTMLResponse)
def url_page(request: Request, user: User = Depends(current_user)):
    return _render(request, "analyze_url.html", user=user)


@router.post("/analyze/url", response_class=HTMLResponse)
async def url_scan(
    request: Request,
    url: str = Form(...),
    csrf_token: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    verify_csrf(request, csrf_token)
    try:
        result = await analyze_url(url.strip())
    except Exception as exc:
        return _error_response(request, str(exc))
    result["enrichment"] = await enrich_result(result, "url")
    result["graph"] = build_graph(result)
    scan = save_scan(db, user, "url", url.strip(), result)
    return _render(request, "result.html", scan=scan, title="URL Analysis", result=result, user=user)


@router.get("/analyze/phishing", response_class=HTMLResponse)
def phishing_page(request: Request, user: User = Depends(current_user)):
    return _render(request, "analyze_phishing.html", user=user)


@router.post("/analyze/phishing", response_class=HTMLResponse)
async def phishing_scan(
    request: Request,
    file: UploadFile = File(...),
    csrf_token: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    verify_csrf(request, csrf_token)
    data = await read_upload_limited(file, settings.max_upload_mb * 1024 * 1024)
    try:
        filename = validate_upload(file.filename or "email.eml", data, settings.max_upload_mb)
        result = analyze_email(data)
    except ValueError as exc:
        return _error_response(request, str(exc))
    except Exception as exc:
        return _error_response(request, f"Email parser error: {exc}")
    result["enrichment"] = await enrich_result(result, "email")
    result["graph"] = build_graph(result)
    scan = save_scan(db, user, "email", filename, result)
    return _render(request, "result.html", scan=scan, title="Phishing Analysis", result=result, user=user)


@router.get("/analyze/malware", response_class=HTMLResponse)
def malware_page(request: Request, user: User = Depends(current_user)):
    return _render(request, "analyze_malware.html", user=user)


@router.post("/analyze/malware", response_class=HTMLResponse)
async def malware_scan(
    request: Request,
    file: UploadFile = File(...),
    csrf_token: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    verify_csrf(request, csrf_token)
    data = await read_upload_limited(file, settings.max_upload_mb * 1024 * 1024)
    try:
        filename = validate_upload(file.filename or "sample.bin", data, settings.max_upload_mb)
    except ValueError as exc:
        return _error_response(request, str(exc))
    try:
        result = analyze_file(filename, data)
    except Exception as exc:
        return _error_response(request, f"Static analyzer error: {exc}")

    digest = result["hashes"]["sha256"]
    storage_root = Path(settings.storage_dir).resolve()
    artifact_dir = storage_root / f"tenant_{user.tenant_id}"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / f"{digest}.sample"
    existed_before = path.exists()
    if not existed_before:
        path.write_bytes(data)
    result["stored_artifact"] = {
        "sha256": digest,
        "storage_key": str(path.relative_to(storage_root)),
        "deduplicated": existed_before,
    }
    result["enrichment"] = await enrich_result(result, "file")
    result["graph"] = build_graph(result)
    scan = save_scan(db, user, "file", filename, result)
    return _render(request, "result.html", scan=scan, title="Malware Static Analysis", result=result, user=user)


@router.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_session)):
    scans = db.query(Scan).filter(Scan.owner_user_id == user.id).order_by(Scan.id.desc()).limit(80).all()
    rows = []
    for scan in scans:
        iocs = scan.result.get("iocs", {}) if isinstance(scan.result, dict) else {}
        ioc_count = sum(len(v) for v in iocs.values() if isinstance(v, list))
        rows.append({
            "scan": scan,
            "ioc_count": ioc_count,
            "summary": (scan.result.get("summary") or scan.result.get("description") or "Evidence analysis completed.")[:180] if isinstance(scan.result, dict) else "Evidence analysis completed.",
            "risk_label": "Critical" if scan.risk_score >= 85 else "High" if scan.risk_score >= 60 else "Medium" if scan.risk_score >= 30 else "Low",
        })
    totals = {
        "scans": len(rows),
        "high": sum(1 for r in rows if r["scan"].risk_score >= 60),
        "iocs": sum(r["ioc_count"] for r in rows),
        "reports": db.query(Report).filter(Report.owner_user_id == user.id).count(),
    }
    return _render(request, "reports.html", user=user, scans=rows, totals=totals, title="My scans & reports")


@router.get("/reports/{scan_id}/{fmt}")
def report_download(scan_id: int, fmt: str, user: User = Depends(current_user), db: Session = Depends(get_session)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.owner_user_id == user.id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    title = f"PhishGuard {scan.scan_type} report #{scan.id}"
    if fmt == "json":
        content, media = report_json(title, scan.result), "application/json"
    elif fmt == "markdown":
        content, media = report_markdown(title, scan.result), "text/markdown"
    elif fmt == "html":
        content, media = report_html(title, scan.result), "text/html"
    elif fmt == "stix":
        content, media = report_stix(title, scan.result), "application/json"
    else:
        raise HTTPException(400, "Unsupported format")
    extension = "json" if fmt == "stix" else fmt
    return Response(
        content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="scan-{scan.id}.{extension}"'},
    )


@router.get("/reports/{scan_id}/share-token")
def report_share_token(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_session)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.owner_user_id == user.id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    token = signed_report_token(scan.id, user.tenant_id)
    return {"token": token, "share_url": f"/shared/{token}"}


@router.get("/shared/{token}", response_class=HTMLResponse)
def shared_report(token: str, request: Request, db: Session = Depends(get_session)):
    parts = token.split(".", 2)
    if len(parts) != 3:
        raise HTTPException(404, "Report not found")
    try:
        scan_id, tenant_id = int(parts[0]), int(parts[1])
    except ValueError:
        raise HTTPException(404, "Report not found")
    if not verify_report_token(token, scan_id, tenant_id):
        raise HTTPException(404, "Report not found")
    scan = db.query(Scan).filter_by(id=scan_id, tenant_id=tenant_id).first()
    if not scan:
        raise HTTPException(404, "Report not found")
    return _render(request, "result.html", scan=scan, title="Shared Report", result=scan.result, user=None)


@router.get("/iocs", response_class=HTMLResponse)
def iocs_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_session)):
    iocs = db.query(IOC).filter(IOC.owner_user_id == user.id).order_by(IOC.id.desc()).limit(200).all()
    return _render(request, "iocs.html", user=user, iocs=iocs)


@router.get("/cases", response_class=HTMLResponse)
def cases_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_session)):
    cases = db.query(Case).filter(Case.owner_user_id == user.id).order_by(Case.id.desc()).all()
    return _render(request, "cases.html", user=user, cases=cases)


@router.post("/cases")
def create_case(
    request: Request,
    title: str = Form(...),
    priority: str = Form("medium"),
    notes: str = Form(""),
    csrf_token: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_session),
):
    verify_csrf(request, csrf_token)
    title = title.strip()
    allowed = {"low", "medium", "high", "critical"}
    if priority not in allowed:
        raise HTTPException(400, "Invalid priority")
    if not title or len(title) > 255:
        raise HTTPException(400, "Case title is required and must be <= 255 characters")
    db.add(Case(tenant_id=user.tenant_id, owner_user_id=user.id, title=title, priority=priority, notes=notes[:10000]))
    db.commit()
    return RedirectResponse("/cases", status_code=303)


@router.get("/analyze/pcap", response_class=HTMLResponse)
def pcap_page(request: Request, user: User = Depends(current_user)):
    return _render(request, "analyze_pcap.html", user=user)

@router.post("/analyze/pcap", response_class=HTMLResponse)
async def pcap_scan(request: Request, file: UploadFile = File(...), csrf_token: str = Form(...), user: User = Depends(current_user), db: Session = Depends(get_session)):
    verify_csrf(request, csrf_token)
    data = await read_upload_limited(file, settings.max_upload_mb * 1024 * 1024)
    try:
        filename = validate_upload(file.filename or "capture.pcap", data, settings.max_upload_mb)
        result = analyze_pcap(data)
    except ValueError as exc:
        return _error_response(request, str(exc))
    result["verdict"] = "suspicious" if result["findings"] else "no-observed-threat"
    result["risk_score"] = min(100, 25 * len(result["findings"]))
    result["iocs"] = {"ip": [item["ip"] for item in result["endpoints"] if item.get("ip")]}
    result["graph"] = {"nodes": [], "edges": []}
    scan = save_scan(db, user, "pcap", filename, result)
    return _render(request, "result.html", scan=scan, title="PCAP Forensics", result=result, user=user)

@router.get("/status", response_class=HTMLResponse)
def status_page(request: Request):
    return _render(request, "status.html")


@router.get("/graph/{scan_id}", response_class=HTMLResponse)
def graph_page(scan_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_session)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.owner_user_id == user.id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    graph = scan.result.get("graph") or build_graph(scan.result)
    return _render(request, "graph.html", user=user, scan=scan, graph=graph)


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_session)):
    profile = db.query(UserProfile).filter_by(user_id=user.id).first()
    if not profile:
        profile = UserProfile(user_id=user.id, display_name=user.email.split("@")[0])
        db.add(profile); db.commit(); db.refresh(profile)
    control = db.query(UserControl).filter_by(user_id=user.id).first()
    return _render(request, "settings.html", user=user, profile=profile, control=control, title="Manage account")
