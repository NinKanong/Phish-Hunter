from __future__ import annotations

import inspect
import asyncio
import time

import ipaddress
import socket
import uuid
import json
import csv
from io import BytesIO, StringIO
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, quote_plus

import httpx

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, Response, JSONResponse, RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session
from phishhunter.db.database import SessionLocal

from phishhunter.analyzers.email_analyzer import analyze_email
from phishhunter.analyzers.email_deep_engine import analyze_email_deep
from phishhunter.services.email_agent import connector_fabric, agent_manifest
from phishhunter.analyzers.file_analyzer import analyze_file
from phishhunter.analyzers.pcap.analyzer import analyze_pcap
from phishhunter.analyzers.url_analyzer import analyze_url
from phishhunter.analyzers.unified_url_domain import tool_fabric_status
from phishhunter.url_domain_analyst.engine import analyze as analyze_url_domain
from phishhunter.url_domain_analyst.workforce.export import workbook_bytes as workforce_workbook_bytes
from phishhunter.url_domain_analyst.attack_surface import build as build_attack_surface
from phishhunter.url_domain_analyst.entity_isolates import build_host_isolate
from phishhunter.analysis.graph_builder import build_graph
from phishhunter.analysis.reporting import build_finding_catalog, build_investigation_summary
from phishhunter.analysis.deep_enhance import enhance_result
from phishhunter.analysis.pcap_deep import augment_pcap
from phishhunter.analysis.depth_contract import capability_manifest
from phishhunter.analysis.deep_services import (
    deep_domain_analysis, deep_feed_analysis, deep_ip_analysis, deep_ioc_analysis,
    deep_phishing_kit_analysis, deep_ransomware_analysis, json_safe, normalize_result,
    sandbox_manifest,
)
from phishhunter.config import settings
from phishhunter.db.database import get_session
from phishhunter.enrichment.registry import connector_catalog
from phishhunter.reports import (report_html, report_json, report_markdown, report_stix, report_pdf, report_ioc_csv, report_connections_csv, report_text, report_bundle, report_export, available_report_formats, executive_summary)
from phishhunter.enrichment.service import enrich_result
from phishhunter.url_domain_analyst.connectors.providers.public_geo import lookup_many as public_geo_lookup
from phishhunter.models import GuestScan, GuestWorkspace, Scan, User, IOC
from phishhunter.security.jwt import decode_token
from phishhunter.security.upload_guard import read_upload_limited, validate_upload
from phishhunter_common.hash import hash_bytes
from phishhunter_common.ioc import extract_iocs
from phishhunter.web.routes import _render

router = APIRouter(tags=["services"])

# In-process result cache keeps isolated modules consistent and prevents every click
# from launching the full deep collection again. The cache is intentionally bounded
# and ephemeral; production deployments can replace it with Redis.
_URL_DOMAIN_CASE_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}
_URL_DOMAIN_CASE_TTL = 600.0

# Live URL/domain investigation jobs. The worker is intentionally in-process for the
# standalone build; production can replace this dictionary with Redis/Celery/Temporal.
_URL_DOMAIN_JOBS: dict[str, dict] = {}
_URL_DOMAIN_JOB_TTL = 3600.0


# Lightweight global-map cache. Public live feeds are polled on demand and cached briefly
# to avoid unnecessary upstream load while the browser refreshes the map.
_LIVE_MAP_CACHE: dict[str, tuple[float, dict]] = {}
_LIVE_MAP_CACHE_TTL = 20.0

async def _live_map_payload(target: str, seed_ips: list[str] | None = None) -> dict:
    from phishhunter.url_domain_analyst.deep_intelligence.normalization import normalize_target
    norm = normalize_target(target)
    host = str(norm.get("hostname") or "")
    result = {
        "version": "DOMINUS-LIVE-MAP-V29",
        "target": host,
        "resolved_ips": [],
        "locations": [],
        "events": [],
        "flights": [],
        "providers": {},
        "errors": [],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    clean_seed=[]
    for raw in (seed_ips or []):
        try:
            ip=ipaddress.ip_address(str(raw).strip())
            if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
                clean_seed.append(str(ip))
        except ValueError:
            continue
    clean_seed=list(dict.fromkeys(clean_seed))[:20]
    cache_key=host+"|"+",".join(clean_seed)
    cached = _LIVE_MAP_CACHE.get(cache_key)
    if cached and time.monotonic() - cached[0] < _LIVE_MAP_CACHE_TTL:
        return cached[1]

    async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
        if norm.get("host_type") in {"ipv4", "ipv6"}:
            try:
                ip = ipaddress.ip_address(host)
                if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
                    result["resolved_ips"] = [host]
                    result["providers"]["Target IP"] = {"status": "observed", "records": 1}
                else:
                    result["errors"].append({"provider": "target", "status": "blocked", "detail": "Private/reserved target IP is not plotted."})
            except ValueError:
                result["errors"].append({"provider": "target", "status": "invalid-ip"})
        else:
            if clean_seed:
                result["resolved_ips"] = clean_seed
                result["providers"]["Scan A/AAAA observations"] = {"status":"observed","records":len(clean_seed)}
            for endpoint, provider in ([] if result["resolved_ips"] else [
                (f"https://cloudflare-dns.com/dns-query?name={quote_plus(host)}&type=A", "Cloudflare DoH"),
                (f"https://dns.google/resolve?name={quote_plus(host)}&type=A", "Google DoH"),
            ]):
                try:
                    r = await client.get(endpoint, headers={"Accept": "application/dns-json"})
                    if r.status_code != 200:
                        raise RuntimeError(f"HTTP {r.status_code}")
                    data = r.json()
                    answers = data.get("Answer") or []
                    ips = []
                    for answer in answers:
                        value = str(answer.get("data") or "").strip()
                        try:
                            ip = ipaddress.ip_address(value)
                            if ip.version == 4 and not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
                                ips.append(str(ip))
                        except ValueError:
                            continue
                    result["providers"][provider] = {"status": "ok", "records": len(answers)}
                    if not result["resolved_ips"] and ips:
                        result["resolved_ips"] = list(dict.fromkeys(ips))[:20]
                except Exception as exc:
                    result["providers"][provider] = {"status": "unavailable"}
                    result["errors"].append({"provider": provider, "status": "unavailable", "detail": str(exc)[:180]})
                if result["resolved_ips"]:
                    break

        if result["resolved_ips"]:
            try:
                locations = await public_geo_lookup(client, result["resolved_ips"], limit=20)
                result["locations"] = [x for x in (locations or []) if isinstance(x, dict) and x.get("lat") is not None and x.get("lon") is not None]
                result["providers"]["IP geolocation"] = {"status": "ok" if result["locations"] else "unavailable", "records": len(result["locations"])}
            except Exception as exc:
                result["errors"].append({"provider": "IP geolocation", "status": "unavailable", "detail": str(exc)[:180]})
        else:
            result["errors"].append({"provider": "IP resolution", "status": "unavailable", "detail": "No public A records returned by configured DoH endpoints."})

        try:
            r = await client.get("https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson")
            if r.status_code == 200:
                data = r.json(); rows = []
                for feature in data.get("features") or []:
                    if not isinstance(feature, dict):
                        continue
                    coords = (feature.get("geometry") or {}).get("coordinates") or []
                    props = feature.get("properties") or {}
                    if len(coords) >= 2 and coords[0] is not None and coords[1] is not None:
                        rows.append({"id": feature.get("id"), "lat": coords[1], "lon": coords[0], "depth": coords[2] if len(coords) > 2 else None, "mag": props.get("mag"), "name": props.get("place"), "time": props.get("time"), "source": "USGS"})
                result["events"] = rows
                result["providers"]["USGS"] = {"status": "live", "records": len(rows)}
            else:
                result["providers"]["USGS"] = {"status": "unavailable"}
        except Exception as exc:
            result["providers"]["USGS"] = {"status": "unavailable"}
            result["errors"].append({"provider": "USGS", "status": "unavailable", "detail": str(exc)[:180]})

        try:
            r = await client.get("https://opensky-network.org/api/states/all")
            if r.status_code == 200:
                data = r.json(); rows = []
                for aircraft in (data.get("states") or [])[:2500]:
                    if not isinstance(aircraft, list) or len(aircraft) < 11 or aircraft[5] is None or aircraft[6] is None:
                        continue
                    rows.append({"icao24": aircraft[0], "callsign": str(aircraft[1] or "").strip(), "country": aircraft[2], "lon": aircraft[5], "lat": aircraft[6], "altitude": aircraft[7], "velocity": aircraft[9], "heading": aircraft[10], "source": "OpenSky"})
                result["flights"] = rows
                result["providers"]["OpenSky"] = {"status": "live", "records": len(rows)}
            else:
                result["providers"]["OpenSky"] = {"status": "unavailable"}
        except Exception as exc:
            result["providers"]["OpenSky"] = {"status": "unavailable"}
            result["errors"].append({"provider": "OpenSky", "status": "unavailable", "detail": str(exc)[:180]})

    _LIVE_MAP_CACHE[cache_key] = (time.monotonic(), result)
    return result

def _job_event(job: dict, event: str, payload: dict | None = None):
    item = {"event": event, "ts": datetime.now(timezone.utc).isoformat(), **(payload or {})}
    job.setdefault("events", []).append(item)
    job["events"] = job["events"][-500:]

def _job_progress(job_id: str, payload: dict):
    job = _URL_DOMAIN_JOBS.get(job_id)
    if not job or job.get("status") in {"completed", "failed"}:
        return
    pct = int(payload.get("percent") or 0)
    job["progress"] = max(0, min(99, pct))
    job["stage"] = str(payload.get("stage") or "collection")
    job["stage_state"] = str(payload.get("state") or "running")
    _job_event(job, "progress", {"percent": job["progress"], "stage": job["stage"], "state": job["stage_state"], "detail": payload.get("detail") or ""})

async def _run_url_domain_job(job_id: str, target: str, profile: str):
    job = _URL_DOMAIN_JOBS.get(job_id)
    if not job:
        return
    try:
        job["status"] = "running"
        job["progress"] = 2
        _job_event(job, "job.started", {"percent": 2, "stage": "intake", "detail": "Target normalized; starting passive-first evidence collection."})
        for pct, stage, detail in [
            (5, "normalization", "URL/domain anatomy and public-target validation"),
            (9, "base collection", "DNS, RDAP, CT and safe HTTP/TLS collection"),
        ]:
            job["progress"] = pct; job["stage"] = stage
            _job_event(job, "progress", {"percent": pct, "stage": stage, "state": "running", "detail": detail})
            await asyncio.sleep(0)

        def callback(payload):
            _job_progress(job_id, payload)

        # The analyzer contains a large amount of network/provider work. Run its
        # event loop in a worker thread so the HTTP/SSE loop remains responsive and
        # the browser receives real progress instead of freezing at 0–9%.
        def _engine_worker():
            return asyncio.run(_analyze_url_domain_cached(target, profile, progress_cb=callback))
        result = await asyncio.to_thread(_engine_worker)
        if not isinstance(result, dict):
            raise TypeError("URL/domain engine returned a non-object result")
        result.setdefault("analysis_engine", {"name": "K4 URL & Domain Analyst", "version": "29.0"})
        result["analysis_engine"]["version"] = "29.0"
        result["job_id"] = job_id
        job["result"] = result
        job["status"] = "completed"
        job["progress"] = 100
        job["stage"] = "complete"
        _job_event(job, "job.completed", {"percent": 100, "stage": "complete", "result_url": f"/services/url-domain-analyst/scan/{job_id}/result"})
    except Exception as exc:
        job["status"] = "failed"
        job["progress"] = 100
        job["error"] = str(exc)[:1000]
        _job_event(job, "job.failed", {"percent": 100, "stage": "error", "error": job["error"]})

def _prune_url_domain_jobs():
    now = time.monotonic()
    stale = [k for k,v in _URL_DOMAIN_JOBS.items() if now - float(v.get("created_mono", now)) > _URL_DOMAIN_JOB_TTL]
    for k in stale:
        _URL_DOMAIN_JOBS.pop(k, None)


async def _analyze_url_domain_cached(target: str, profile: str = "deep", progress_cb=None) -> dict:
    import time
    key=(str(target or "").strip().lower(), str(profile or "deep").strip().lower())
    now=time.monotonic()
    cached=_URL_DOMAIN_CASE_CACHE.get(key)
    if cached and (now-cached[0]) < _URL_DOMAIN_CASE_TTL:
        if progress_cb:
            try:
                progress_cb({"stage":"cache","state":"completed","percent":98,"detail":"Reused a recent evidence case from the bounded cache."})
            except Exception:
                pass
        return cached[1]
    result=analyze_url_domain(str(target or "").strip(), profile=profile, progress_cb=progress_cb)
    if inspect.isawaitable(result):
        result=await result
    if not isinstance(result, dict):
        result={"target":target,"domain":target,"verdict":"unknown","risk_score":0}
    _URL_DOMAIN_CASE_CACHE[key]=(now,result)
    # prune oldest entries when the cache grows beyond a small operational bound
    if len(_URL_DOMAIN_CASE_CACHE) > 64:
        oldest=min(_URL_DOMAIN_CASE_CACHE.items(), key=lambda item:item[1][0])[0]
        _URL_DOMAIN_CASE_CACHE.pop(oldest,None)
    return result

SERVICE_CATALOG = {
    "email-analyst": {
        "title": "Email Analyst",
        "eyebrow": "PHISHING ANALYSIS",
        "description": "Deep MIME, header, authentication, content, URL, attachment, IOC and phishing-risk analysis.",
        "input": "email",
        "features": [
            "EML / MSG / MBOX / EMLX / MHT intake",
            "Received-hop timeline and sender infrastructure",
            "SPF, DKIM, DMARC and ARC evidence",
            "HTML, hidden-text, tracking-pixel and form analysis",
            "URL, attachment and IOC extraction",
            "Explainable risk scoring and MITRE mapping",
        ],
    },
    "url-domain-analyst": {
        "title": "URL & Domain Analyst",
        "eyebrow": "UNIFIED OSINT · IR · INFRASTRUCTURE",
        "description": "A single investigation workspace for URL and domain intelligence: RDAP, DNS, CT, TLS, HTTP, reputation, breach exposure, technology profiling, relationship graphing and evidence-led AI triage.",
        "input": "url-domain",
        "features": [
            "Upload or submit a URL/domain target, then start a controlled investigation",
            "WHOIS/RDAP, registration lifecycle, public entities and domain age",
            "Deep DNS record matrix, DNSSEC signals, MX/NS/TXT and current reverse DNS",
            "Certificate Transparency history and passive subdomain discovery",
            "SSRF-aware HTTP/HTTPS inspection, redirects, forms, headers and TLS",
            "Technology stack fingerprinting and infrastructure relationships",
            "VirusTotal, urlscan.io, Safe Browsing, AbuseIPDB and verified-domain HIBP enrichment when configured",
            "Breach/leak intelligence boundary with explicit provider status and no fabricated dark-web results",
            "Investigation graph with source-backed pivots and confidence",
            "Explainable risk model, evidence ledger, timeline, MITRE mappings and analyst task plan",
            "200+ named OSINT/security integration points with live-vs-catalog status",
            "Optional OpenAI Responses API investigation brief using stored=false request semantics",
        ],
    },
    "file-analyst": {
        "title": "File Analyst",
        "eyebrow": "STATIC ANALYSIS",
        "description": "Static triage for suspicious files with hashes, entropy, strings, metadata and behavioral indicators.",
        "input": "file",
        "features": [
            "Magic-byte and MIME identification",
            "MD5 / SHA1 / SHA256 / fuzzy hashes",
            "Entropy, strings and suspicious API signals",
            "PE, document and script indicators",
            "YARA and capability-oriented findings",
            "IOC extraction and threat-intel enrichment",
        ],
    },
    "ip-analyst": {
        "title": "IP Analyst",
        "eyebrow": "INFRASTRUCTURE",
        "description": "Profile IPv4/IPv6 indicators with DNS, ASN, hostname and reputation context.",
        "input": "ip",
        "features": [
            "IPv4 and IPv6 validation",
            "Reverse DNS and local resolver context",
            "Address classification",
            "IOC correlation",
            "External reputation connectors when configured",
            "Evidence-backed risk assessment",
        ],
    },
    "pcap-analyst": {
        "title": "PCAP Analyst",
        "eyebrow": "NETWORK ARTIFACTS",
        "description": "A dedicated network-forensics investigation center for PCAP and sibling network artifacts: Zeek, Suricata, NetFlow/IPFIX, firewall, proxy, DNS and DHCP telemetry.",
        "input": "network-artifacts",
        "features": [
            "PCAP / PCAPNG packet and flow parsing",
            "Zeek conn/http/dns/ssl/SMB/Kerberos log correlation",
            "Suricata EVE alert and flow correlation",
            "NetFlow/IPFIX five-tuple and volume analysis",
            "Firewall, proxy, DNS and DHCP log ingestion",
            "Victim / external-source / C2 candidate identification",
            "IOC explorer, unified timeline and network graph",
            "Evidence-backed MITRE mapping and explainable risk",
            "Real-time job progress over WebSocket",
            "Investigation report and artifact evidence locker",
        ],
    },
    "malware-analyst": {
        "title": "Malware Analyst",
        "eyebrow": "MALWARE TRIAGE",
        "description": "Static malware triage with hashes, file structure, strings, capabilities and intelligence context.",
        "input": "file",
        "features": [
            "Sample identification and hashing",
            "PE/ELF-oriented static indicators",
            "Strings, entropy and suspicious API signals",
            "Packer and executable indicators",
            "IOC and MITRE-oriented findings",
            "Optional sandbox integration boundary",
        ],
    },
    "ransomware-analyst": {
        "title": "Ransomware Analyst",
        "eyebrow": "INCIDENT TRIAGE",
        "description": "Collect defensive ransomware indicators from samples, notes and incident artifacts.",
        "input": "file",
        "features": [
            "Ransom-note and artifact triage",
            "Hash and file-type identification",
            "Suspicious command and persistence indicators",
            "IOC extraction",
            "MITRE-oriented evidence",
            "Incident-report-ready output",
        ],
    },
    "ioc-analyst": {
        "title": "IOC Analyst",
        "eyebrow": "INDICATOR INTELLIGENCE",
        "description": "Normalize, classify and correlate IPs, domains, URLs, hashes and email indicators.",
        "input": "ioc",
        "features": [
            "Automatic IOC type detection",
            "Defanging/refanging-safe handling",
            "Cross-indicator correlation",
            "Threat-intel enrichment",
            "Confidence and source visibility",
            "JSON/STIX-ready evidence",
        ],
    },
    "phishing-kit-analyst": {
        "title": "Phishing Kit Analyst",
        "eyebrow": "PHISHING INFRASTRUCTURE",
        "description": "Inspect authorized phishing-page artifacts for forms, obfuscation, exfiltration indicators and infrastructure.",
        "input": "file",
        "features": [
            "HTML and JavaScript inspection",
            "Credential-form discovery",
            "Obfuscation indicators",
            "URL and endpoint extraction",
            "Brand-impersonation evidence",
            "Campaign correlation-ready IOC output",
        ],
    },
    "threat-intelligence": {
        "title": "Threat Intelligence",
        "eyebrow": "CENTRAL INTELLIGENCE",
        "description": "Central enrichment and correlation workspace for indicators, feeds, campaigns and relationships.",
        "input": "ioc",
        "features": [
            "Connector catalog and provider health",
            "IOC enrichment framework",
            "Campaign and actor relationship model",
            "Feed ingestion boundary",
            "Graph-ready relationships",
            "Export-ready structured intelligence",
        ],
    },
    "sandbox": {
        "title": "Sandbox",
        "eyebrow": "ISOLATED EXECUTION",
        "description": "Unified interface for configured sandbox providers. Local web analysis never executes uploaded malware.",
        "input": "sandbox",
        "features": [
            "CAPEv2 integration boundary",
            "ANY.RUN / Joe Sandbox / Hybrid Analysis adapters",
            "Result normalization",
            "Submission status and evidence",
            "Provider health visibility",
            "Explicit isolation requirement",
        ],
    },
    "reports": {
        "title": "Reports",
        "eyebrow": "REPORTING",
        "description": "Collect, review and export analysis results in clean analyst-friendly formats.",
        "input": "reports",
        "features": [
            "HTML / JSON / Markdown / STIX exports",
            "Evidence and IOC sections",
            "MITRE-oriented findings",
            "Shareable report routes",
            "Guest-mode watermarking",
            "Ready for enterprise report extensions",
        ],
    },
    "cases": {
        "title": "Cases",
        "eyebrow": "INVESTIGATION",
        "description": "Organize investigations and bring evidence from multiple analyst modules into one case.",
        "input": "cases",
        "features": [
            "Open and track investigations",
            "Priority and status",
            "Evidence references",
            "Analyst notes",
            "IOC and scan correlation",
            "Final-report workflow",
        ],
    },
    "campaigns": {
        "title": "Campaigns",
        "eyebrow": "THREAT RESEARCH",
        "description": "Group related indicators and observations into campaign-level investigations.",
        "input": "catalog",
        "features": [
            "Campaign entities",
            "Related IOCs",
            "Infrastructure relationships",
            "Evidence timeline",
            "Confidence-aware attribution",
            "Report-ready summaries",
        ],
    },
    "actors": {
        "title": "Threat Actors",
        "eyebrow": "THREAT RESEARCH",
        "description": "Maintain evidence-backed actor profiles without turning correlation into unsupported attribution.",
        "input": "catalog",
        "features": [
            "Actor profiles",
            "Observed infrastructure",
            "Malware relationships",
            "Campaign relationships",
            "MITRE technique references",
            "Attribution guardrails",
        ],
    },
    "graph": {
        "title": "IOC Graph",
        "eyebrow": "RELATIONSHIP ANALYSIS",
        "description": "Explore relationships between scans, IOCs, domains, IPs, hashes and MITRE techniques.",
        "input": "graph",
        "features": [
            "IOC relationship visualization",
            "Scan-to-indicator links",
            "Infrastructure pivots",
            "Technique relationships",
            "Investigation pivots",
            "Export-ready graph data",
        ],
    },
    "feeds": {
        "title": "Threat Feeds",
        "eyebrow": "INTELLIGENCE FEEDS",
        "description": "Review configured public and private feed connectors and their ingestion state.",
        "input": "feeds",
        "features": [
            "PhishTank / OpenPhish connectors",
            "URLhaus / ThreatFox / MalwareBazaar boundaries",
            "Custom RSS and TAXII-ready architecture",
            "Feed health",
            "Ingestion statistics",
            "Tenant-aware feed configuration",
        ],
    },
}

def _guest_id(request: Request) -> str:
    guest_id = request.cookies.get("k4_guest_id")
    return guest_id if guest_id and len(guest_id) <= 64 else str(uuid.uuid4())

def _guest_response(request: Request, response: HTMLResponse, guest_id: str) -> HTMLResponse:
    if request.cookies.get("k4_guest_id") != guest_id:
        response.set_cookie(
            "k4_guest_id",
            guest_id,
            max_age=24 * 60 * 60,
            httponly=True,
            samesite="lax",
            secure=request.url.scheme == "https",
            path="/",
        )
    return response

def _guest_record(db: Session, guest_id: str, scan_type: str, target: str, result: dict) -> GuestScan:
    now = datetime.now(timezone.utc)
    row = GuestScan(
        guest_id=guest_id,
        scan_type=scan_type,
        target=target,
        verdict=str(result.get("verdict", "unknown")),
        risk_score=int(result.get("risk_score", 0)),
        result=result,
        created_at=now,
        expires_at=now + timedelta(hours=24),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row

def _optional_user(request: Request, db: Session):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        data = decode_token(token, "access")
        return db.get(User, int(data["sub"]))
    except (Exception, KeyError, TypeError, ValueError):
        return None

def _save_authenticated_scan(db: Session, user: User, service_key: str, target: str, result: dict):
    scan = Scan(tenant_id=user.tenant_id, owner_user_id=user.id, scan_type=service_key, target=target[:10000], status="completed", verdict=str(result.get("verdict", "unknown")), risk_score=int(result.get("risk_score", 0) or 0), result=result)
    db.add(scan); db.flush()
    for kind, values in (result.get("iocs") or {}).items():
        if isinstance(values, list):
            for value in values[:5000]:
                text = str(value).strip()
                if text:
                    db.add(IOC(tenant_id=user.tenant_id, owner_user_id=user.id, kind=str(kind), value=text, source_scan_id=scan.id))
    db.commit(); db.refresh(scan)
    return scan

def _result_page(request: Request, service_key: str, result: dict, target: str, guest_id: str, db: Session) -> HTMLResponse:
    result = enhance_result(normalize_result(result), service_key, target)
    # Every result page has a stable schema so specialized operational services cannot
    # leave Jinja Undefined values that later break JSON rendering or persistence.
    result.setdefault("analysis_engine", {"name": "K4 Service Engine", "version": "12.0"})
    result.setdefault("iocs", {})
    result.setdefault("evidence", [])
    result.setdefault("mitre_techniques", [])
    result.setdefault("verdict", "unknown")
    result.setdefault("risk_score", 0)
    result.setdefault("domain", target)
    result.setdefault("target", target)
    result.setdefault("target_type", "domain")
    result.setdefault("registered_domain", result.get("domain") or target)
    result.setdefault("url", target if str(target).lower().startswith(("http://", "https://")) else "")
    for _key, _default in (("domain_overview", {}),("url_forensics", {}),("breach_intelligence", {"status":"provider-dependent","records":[]}),("whois_rdap", {}),("dns", {}),("ip_intelligence", {}),("reputation", {}),("http", {}),("osint_pivots", []),("timeline", [])): 
        if not isinstance(result.get(_key), (dict, list)): result[_key] = _default
    if isinstance(result.get("breach_intelligence"), dict):
        result["breach_intelligence"].setdefault("status", "provider-dependent")
        result["breach_intelligence"].setdefault("records", [])
    if not isinstance(result.get("breach_posture"), dict):
        result["breach_posture"] = {"known_provider_connectors": [], "direct_dark_web_crawl": False, "note": "provider-dependent"}
    result["breach_posture"].setdefault("known_provider_connectors", [])
    result["breach_posture"].setdefault("direct_dark_web_crawl", False)
    result.setdefault("certificate_transparency", {})
    if not isinstance(result.get("certificate_transparency"), dict): result["certificate_transparency"] = {}
    result.setdefault("chain_of_custody", {"package_sha256": ""})
    if not isinstance(result.get("chain_of_custody"), dict): result["chain_of_custody"] = {"package_sha256": ""}
    result["chain_of_custody"].setdefault("package_sha256", "")
    result["graph"] = result.get("graph") or build_graph(result)
    # Normalize all collection-shaped fields consumed by the isolated URL/domain UI.
    if not isinstance(result.get("risk"), dict): result["risk"] = {"score": result.get("risk_score", 0), "verdict": result.get("verdict", "unknown"), "signals": [], "confidence": 50}
    result["risk"].setdefault("signals", [])
    for _k in ("events", "entities", "name_servers", "status_codes"):
        if not isinstance(result["whois_rdap"].get(_k), list): result["whois_rdap"][_k] = []
    if not isinstance(result["whois_rdap"].get("domain_age_days"), (int,float)) and result["whois_rdap"].get("domain_age_days") is not None: result["whois_rdap"]["domain_age_days"] = None
    if not isinstance(result["dns"].get("records"), dict): result["dns"]["records"] = {}
    if not isinstance(result["dns"].get("reverse_dns"), dict): result["dns"]["reverse_dns"] = {}
    for _t,_rows in list(result["dns"]["records"].items()):
        if not isinstance(_rows, list): result["dns"]["records"][_t] = []
    for _k in ("forms", "links", "scripts", "cookies"):
        if not isinstance(result["http"].get(_k), list): result["http"][_k] = []
    if not isinstance(result["http"].get("headers"), dict): result["http"]["headers"] = {}
    if not isinstance(result.get("ip_intelligence"), list): result["ip_intelligence"] = []
    if not isinstance(result.get("technology"), list): result["technology"] = []
    if not isinstance(result.get("security_headers"), dict): result["security_headers"] = {}
    if not isinstance(result.get("dns_posture"), dict): result["dns_posture"] = {"total_records":0}
    if not isinstance(result.get("certificate_posture"), dict): result["certificate_posture"] = {"ct_hostname_count":0}
    if not isinstance(result.get("tls"), dict): result["tls"] = {}
    if not isinstance(result.get("http_posture"), dict): result["http_posture"] = {}
    if not isinstance(result.get("dns_authentication"), dict): result["dns_authentication"] = {}
    if not isinstance(result.get("network_associations"), dict): result["network_associations"] = {"current_ips":[],"mx_hosts":[],"name_servers":[],"reverse_dns":{}}
    if not isinstance(result.get("url_forensics"), dict): result["url_forensics"] = {}
    if not isinstance(result.get("certificate_transparency"), dict): result["certificate_transparency"] = {}
    for _k in ("certificates","names"):
        if not isinstance(result["certificate_transparency"].get(_k), list): result["certificate_transparency"][_k] = []
    result.setdefault("tool_fabric", tool_fabric_status())
    if not isinstance(result.get("tool_fabric"), dict): result["tool_fabric"] = tool_fabric_status()
    result["tool_fabric"].setdefault("items", [])
    result["tool_fabric"].setdefault("catalog_count", len(result["tool_fabric"].get("items", [])))
    # Stable vNext containers prevent provider failures from breaking a specialized pane.
    vnext = result.get("url_domain_vnext") if isinstance(result.get("url_domain_vnext"), dict) else {}
    vnext.setdefault("version", "URL-DOMAIN-V22-GLOBAL-DEEP")
    vnext.setdefault("geo_intelligence", {"countries":[],"hosting_networks":[],"map_points":[],"provider_rows":[],"netblocks":[]})
    if not isinstance(vnext.get("geo_intelligence"), dict):
        vnext["geo_intelligence"] = {"countries":[],"hosting_networks":[],"map_points":[],"provider_rows":[],"netblocks":[]}
    vnext["geo_intelligence"].setdefault("countries", [])
    vnext["geo_intelligence"].setdefault("hosting_networks", [])
    vnext["geo_intelligence"].setdefault("map_points", [])
    vnext["geo_intelligence"].setdefault("provider_rows", [])
    vnext["geo_intelligence"].setdefault("netblocks", [])
    vnext.setdefault("workforce_intelligence", {"company_name":None,"industry":None,"company_type":None,"founded":None,"employee_size_range":None,"employee_exact_count":None,"linkedin_urls":[],"employee_rows":[],"employee_observation_count":0})
    if not isinstance(vnext.get("workforce_intelligence"), dict):
        vnext["workforce_intelligence"] = {"company_name":None,"industry":None,"company_type":None,"founded":None,"employee_size_range":None,"employee_exact_count":None,"linkedin_urls":[],"employee_rows":[],"employee_observation_count":0}
    for _k, _default in (("linkedin_urls", []),("employee_rows", []),("employee_observation_count", 0)): vnext["workforce_intelligence"].setdefault(_k, _default)
    vnext.setdefault("wappalyzer", {"technologies":[]})
    if not isinstance(vnext.get("wappalyzer"), dict): vnext["wappalyzer"] = {"technologies":[]}
    vnext["wappalyzer"].setdefault("technologies", [])
    vnext.setdefault("attack_surface", {"status":"provider-dependent","summary":{},"a_records":[],"services":[],"countries":[],"hosting_networks":[]})
    if not isinstance(vnext.get("attack_surface"), dict): vnext["attack_surface"] = {"status":"provider-dependent","summary":{},"a_records":[],"services":[],"countries":[],"hosting_networks":[]}
    for _k,_default in (("summary",{}),("a_records",[]),("services",[]),("countries",[]),("hosting_networks",[]),("subdomains",[]),("cname_records",[]),("mx_records",[]),("ns_records",[])):
        vnext["attack_surface"].setdefault(_k,_default)
    for _k,_default in (("hosting_summary",{}),("hosting_candidates",[]),("cloud_attribution",{}),("ai_task_plan",{}),("search_plan",{}),("osint_deep",{}),("security_stack_observables",{"observations":[]}),("wappalyzer",{"technologies":[]})):
        vnext.setdefault(_k,_default)
    if not isinstance(vnext.get("hosting_candidates"), list): vnext["hosting_candidates"] = []
    for _k in ("hosting_summary","cloud_attribution","ai_task_plan","search_plan","osint_deep"): 
        if not isinstance(vnext.get(_k), dict): vnext[_k] = {}
    vnext["search_plan"].setdefault("queries", []) if isinstance(vnext.get("search_plan"), dict) else None
    vnext["osint_deep"].setdefault("pivots", []) if isinstance(vnext.get("osint_deep"), dict) else None
    vnext["wappalyzer"].setdefault("technologies", []) if isinstance(vnext.get("wappalyzer"), dict) else None
    vnext["third_party_services"].setdefault("observations", []) if isinstance(vnext.get("third_party_services"), dict) else None
    vnext["security_stack_observables"].setdefault("observations", []) if isinstance(vnext.get("security_stack_observables"), dict) else None
    vnext["deep_reasoning"].setdefault("summary", "") if isinstance(vnext.get("deep_reasoning"), dict) else None
    vnext["ai_task_plan"].setdefault("tasks", []) if isinstance(vnext.get("ai_task_plan"), dict) else None
    vnext.setdefault("services_banners", {"rows":[]})
    if not isinstance(vnext.get("services_banners"), dict): vnext["services_banners"] = {"rows":[]}
    vnext["services_banners"].setdefault("rows", [])
    vnext.setdefault("third_party_services", {"observations":[]})
    if isinstance(vnext.get("third_party_services"), list):
        vnext["third_party_services"] = {"observations": vnext["third_party_services"]}
    elif not isinstance(vnext.get("third_party_services"), dict):
        vnext["third_party_services"] = {"observations": []}
    vnext["third_party_services"].setdefault("observations", [])
    vnext.setdefault("security_stack_observables", {"observations":[]})
    if isinstance(vnext.get("security_stack_observables"), list):
        vnext["security_stack_observables"] = {"observations": vnext["security_stack_observables"]}
    elif not isinstance(vnext.get("security_stack_observables"), dict):
        vnext["security_stack_observables"] = {"observations": []}
    vnext["security_stack_observables"].setdefault("observations", [])
    vnext.setdefault("osint_deep", {"pivots":[]})
    if not isinstance(vnext.get("osint_deep"), dict): vnext["osint_deep"] = {"pivots":[]}
    vnext["osint_deep"].setdefault("pivots", [])
    vnext.setdefault("exposure_matrix", {})
    if not isinstance(vnext.get("exposure_matrix"), dict): vnext["exposure_matrix"] = {}
    vnext.setdefault("deep_reasoning", {})
    if not isinstance(vnext.get("deep_reasoning"), dict): vnext["deep_reasoning"] = {"summary": str(vnext.get("deep_reasoning"))}
    vnext.setdefault("provider_error_ledger", [])
    if not isinstance(vnext.get("provider_error_ledger"), list): vnext["provider_error_ledger"] = []
    result["url_domain_vnext"] = vnext
    result["executive_summary"] = executive_summary(result)
    result["enrichment"] = result.get("enrichment") or {"status": "not_requested", "providers": []}
    result["finding_catalog"] = build_finding_catalog(result)
    result["investigation_summary"] = build_investigation_summary(result)
    result["ioc_count"] = sum(len(v) for v in (result.get("iocs") or {}).values() if isinstance(v, list))
    result["host_profiles"] = (result.get("network_assessment") or {}).get("internal_host_profiles", result.get("host_profiles", []))
    if service_key != "url-domain-analyst" or not isinstance(result.get("ai_analysis"), dict):
        result["ai_analysis"] = {
            "mode": "local-evidence-copilot",
            "status": "ready",
            "briefing": (
                f"The {SERVICE_CATALOG[service_key]['title']} engine completed analysis with "
                f"risk {int(result.get('risk_score', 0) or 0)}/100, {len(result.get('finding_catalog', []))} finding records, "
                f"and {int(result.get('ioc_count', 0))} extracted IOC values. "
                + ((result.get('network_assessment') or {}).get('assessment_note', 'Review the evidence and correlated pivots before making a disposition.'))
            ),
            "limitations": "This local copilot summarizes engine evidence. It does not independently verify maliciousness, compromise, attribution or intent.",
        }
    result["ai_analysis"].setdefault("mode", "local-evidence-copilot")
    result["ai_analysis"].setdefault("status", "ready")
    result["ai_analysis"].setdefault("briefing", "Review returned evidence and correlated pivots before disposition.")
    result["ai_analysis"].setdefault("limitations", "The local copilot summarizes engine evidence only.")
    result["url_domain_vnext_status"] = result.get("url_domain_vnext_status") or {"status":"completed"}
    result["report_formats"] = available_report_formats() + [{"key":"pdf","label":"PDF","media_type":"application/pdf","extension":"pdf"},{"key":"ioc-csv","label":"IOC CSV","media_type":"text/csv","extension":"iocs.csv"},{"key":"connections-csv","label":"Connections CSV","media_type":"text/csv","extension":"connections.csv"},{"key":"bundle-zip","label":"Complete ZIP","media_type":"application/zip","extension":"zip"}]
    result = normalize_result(result)
    user = _optional_user(request, db)
    if user:
        row = _save_authenticated_scan(db, user, service_key, target, result)
        persistence = "account"
        guest_mode = False
    else:
        row = _guest_record(db, guest_id, service_key, target, result)
        persistence = "guest"
        guest_mode = True
    context = {
        "service": SERVICE_CATALOG[service_key], "service_key": service_key, "result": result,
        "guest_scan": row if guest_mode else None, "saved_scan": row if not guest_mode else None,
        "guest": guest_mode, "persistence": persistence, "user": user,
        "title": f"{SERVICE_CATALOG[service_key]['title']} Result",
    }
    response = _render(request, "email_result.html" if service_key == "email-analyst" else ("url_domain_result.html" if service_key == "url-domain-analyst" else "guest_result.html"), **context)
    return _guest_response(request, response, guest_id) if guest_mode else response

@router.get("/services", response_class=HTMLResponse)
def services_index(request: Request):
    response = _render(request, "services_index.html", services=SERVICE_CATALOG, title="Services")
    return _guest_response(request, response, _guest_id(request))

def _register_service_page(key: str):
    path = f"/services/{key}"
    async def page(request: Request):
        service = SERVICE_CATALOG[key]
        guest_id = _guest_id(request)
        db = SessionLocal()
        try:
            user = _optional_user(request, db)
            context = {"service": service, "service_key": key, "services": SERVICE_CATALOG, "guest": not bool(user), "user": user, "authenticated": bool(user), "title": service["title"], "capabilities": capability_manifest(key), "tool_catalog": tool_fabric_status().get("items", []) if key == "url-domain-analyst" else []}
            template = "network_artifacts.html" if key == "pcap-analyst" else ("email_analyst_workspace.html" if key == "email-analyst" else ("url_domain_workspace.html" if key == "url-domain-analyst" else "service_workspace.html"))
            response = _render(request, template, **context)
            return _guest_response(request, response, guest_id) if not user else response
        finally:
            db.close()
    page.__name__ = f"service_{key.replace('-', '_')}"
    router.add_api_route(path, page, methods=["GET"], response_class=HTMLResponse)

for _key in SERVICE_CATALOG:
    _register_service_page(_key)

@router.get("/services/url-analyst", response_class=HTMLResponse)
@router.get("/services/domain-analyst", response_class=HTMLResponse)
async def legacy_url_domain_get(request: Request):
    return RedirectResponse(url="/services/url-domain-analyst", status_code=307)

@router.post("/services/url-domain-analyst/scan", response_class=JSONResponse)
async def start_url_domain_scan(request: Request, target: str = Form(""), profile: str = Form("deep")):
    """Start a real asynchronous URL/domain investigation and return immediately."""
    value = (target or "").strip()
    if not value:
        return JSONResponse({"status": "error", "error": "Enter a URL or domain."}, status_code=400)
    selected = (profile or "deep").strip().lower()
    if selected not in {"quick", "standard", "deep", "forensic"}:
        selected = "deep"
    _prune_url_domain_jobs()
    job_id = uuid.uuid4().hex
    _URL_DOMAIN_JOBS[job_id] = {
        "id": job_id, "target": value, "profile": selected, "status": "queued",
        "progress": 0, "stage": "queued", "stage_state": "queued",
        "created_mono": time.monotonic(), "created_at": datetime.now(timezone.utc).isoformat(),
        "events": [],
    }
    _job_event(_URL_DOMAIN_JOBS[job_id], "job.queued", {"percent": 0, "stage": "queued", "detail": "Investigation accepted."})
    asyncio.create_task(_run_url_domain_job(job_id, value, selected))
    response = JSONResponse({
        "status": "accepted", "job_id": job_id, "target": value, "profile": selected,
        "stream_url": f"/services/url-domain-analyst/scan/{job_id}/events",
        "result_url": f"/services/url-domain-analyst/scan/{job_id}/result",
    }, status_code=202)
    return _guest_response(request, response, _guest_id(request))

@router.get("/services/url-domain-analyst/scan/{job_id}/status", response_class=JSONResponse)
async def url_domain_scan_status(job_id: str):
    job = _URL_DOMAIN_JOBS.get(job_id)
    if not job:
        return JSONResponse({"status": "not_found", "job_id": job_id}, status_code=404)
    return JSONResponse({k: job.get(k) for k in ("id","target","profile","status","progress","stage","stage_state","error","created_at")})

@router.get("/services/url-domain-analyst/scan/{job_id}/events")
async def url_domain_scan_events(job_id: str):
    async def stream():
        sent = 0
        idle = 0
        while idle < 480:
            job = _URL_DOMAIN_JOBS.get(job_id)
            if not job:
                yield "event: job.failed\ndata: {\"error\":\"Investigation job not found or expired.\"}\n\n"
                return
            events = job.get("events", [])
            while sent < len(events):
                event = events[sent]; sent += 1
                name = event.get("event", "message")
                data = json.dumps({k:v for k,v in event.items() if k != "event"}, ensure_ascii=False)
                yield f"event: {name}\ndata: {data}\n\n"
            if job.get("status") in {"completed", "failed"}:
                return
            idle += 1
            yield ": keepalive\n\n"
            await asyncio.sleep(0.25)
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@router.get("/services/url-domain-analyst/scan/{job_id}/result", response_class=HTMLResponse)
async def url_domain_scan_result(request: Request, job_id: str):
    job = _URL_DOMAIN_JOBS.get(job_id)
    if not job:
        return _render(request, "service_error.html", service=SERVICE_CATALOG["url-domain-analyst"], error="Investigation job not found or expired.", title="Investigation Not Found")
    if job.get("status") != "completed":
        return RedirectResponse(url=f"/services/url-domain-analyst?job={job_id}", status_code=303)
    db = SessionLocal()
    try:
        return _result_page(request, "url-domain-analyst", job["result"], job["target"], _guest_id(request), db)
    finally:
        db.close()

@router.post("/services/url-analyst", response_class=HTMLResponse)
@router.post("/services/domain-analyst", response_class=HTMLResponse)
@router.post("/services/url-domain-analyst", response_class=HTMLResponse)
async def guest_url_domain_analysis(request: Request, target: str = Form(""), target_file: UploadFile | None = File(None), url: str = Form(""), domain: str = Form(""), profile: str = Form("deep")):
    guest_id = _guest_id(request)
    value = (target or url or domain or "").strip()
    try:
        if target_file and target_file.filename:
            data = await target_file.read()
            if len(data) > 1_000_000:
                raise ValueError("Target file is too large; keep intake lists under 1 MB.")
            text = data.decode("utf-8", "replace").strip()
            # Accept one URL/domain per line, JSON {target: ...}, or a text export.
            if text.startswith("{"):
                try:
                    obj=json.loads(text)
                    candidate=str(obj.get("target") or obj.get("url") or obj.get("domain") or "").strip()
                    if candidate: value=candidate
                except Exception:
                    pass
            if not value:
                for line in text.splitlines():
                    line=line.strip().strip(',;')
                    if line and not line.startswith('#'):
                        value=line
                        break
        if not value:
            raise ValueError("Enter a domain or URL before starting the investigation. The target field is required.")
        # Use the uploaded/input value as the case seed. The deep engine performs all
        # provider-safe enrichment behind its own bounded stages.
        selected_profile = profile.strip().lower() if profile else 'deep'
        if selected_profile not in {'deep','forensic','quick'}: selected_profile='deep'
        result = await _analyze_url_domain_cached(value, selected_profile)
        result["enrichment"] = {"status": "completed" if result.get("provider_results") else "provider_optional", "providers": result.get("provider_results", {})}
    except Exception as exc:
        # Never dead-end the investigation on an upstream/provider exception. Return a structured partial case.
        result = {"target": value, "domain": value, "verdict":"unknown", "risk_score":0, "base_collection_error":str(exc)[:500], "url_domain_vnext": {"version":"URL-DOMAIN-VNEXT-12.0","provider_error_ledger":[{"stage":"route","error":str(exc)[:500],"recoverable":True}],"geo_intelligence":{"countries":[],"hosting_networks":[],"map_points":[]},"workforce_intelligence":{"employee_rows":[],"employee_observation_count":0,"linkedin_urls":[]},"third_party_services":[],"security_stack_observables":[]}}
    db = SessionLocal()
    try:
        return _result_page(request, "url-domain-analyst", result, value, guest_id, db)
    finally:
        db.close()

@router.post("/services/url-domain-analyst/export/workforce.xlsx")
async def export_url_domain_workforce(domain: str = Form(""), rows_json: str = Form("[]")):
    """Export only provider/API-returned public workforce observations. Never scrapes LinkedIn."""
    try:
        rows=json.loads(rows_json or "[]")
        if not isinstance(rows,list): rows=[]
        rows=[x for x in rows if isinstance(x,dict)][:5000]
    except Exception:
        rows=[]
    data=workforce_workbook_bytes(rows, domain.strip()[:255])
    return StreamingResponse(BytesIO(data), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition":"attachment; filename=phishhunter-workforce.xlsx"})


@router.post("/services/url-domain-analyst/export/attack-surface.csv")
async def export_url_domain_attack_surface(domain: str = Form(""), rows_json: str = Form("[]")):
    """Export provider-returned DNS/attack-surface rows as CSV."""
    try:
        rows = json.loads(rows_json or "[]")
    except Exception:
        rows = []
    if not isinstance(rows, list):
        rows = []
    fields = ["host","ip","asn","asn_name","asn_range","open_services","ptr","country","country_code","reverse_ip_neighbor_count","source"]
    out = StringIO(); writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore"); writer.writeheader()
    for row in rows[:10000]:
        if not isinstance(row, dict):
            continue
        normalized = dict(row)
        normalized["open_services"] = ", ".join(str(x) for x in (row.get("open_services") or []))
        writer.writerow(normalized)
    return Response(out.getvalue().encode("utf-8"), media_type="text/csv", headers={"Content-Disposition":"attachment; filename=phishhunter-attack-surface.csv"})


@router.post("/services/url-domain-analyst/export/services.csv")
async def export_url_domain_services(domain: str = Form(""), rows_json: str = Form("[]")):
    """Export normalized DNS/HTTP service-banner observations as CSV."""
    try:
        rows=json.loads(rows_json or "[]")
    except Exception:
        rows=[]
    if not isinstance(rows,list): rows=[]
    fields=["host","ip","protocol","port","port_inference","service","product","version","server","title","common_name","source"]
    out=StringIO(); writer=csv.DictWriter(out,fieldnames=fields,extrasaction="ignore"); writer.writeheader()
    for row in rows[:10000]:
        if isinstance(row,dict): writer.writerow(row)
    return Response(out.getvalue().encode("utf-8"),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=phish-hunter-services.csv"})


@router.get("/services/url-domain-analyst/api/live-map", response_class=JSONResponse)
async def url_domain_live_map(request: Request, target: str = "", ips: str = ""):
    try:
        if not target.strip():
            return JSONResponse({"error": "target is required"}, status_code=400)
        seed_ips=[x.strip() for x in ips.split(",") if x.strip()]
        return JSONResponse(await _live_map_payload(target.strip(), seed_ips=seed_ips))
    except Exception as exc:
        return JSONResponse({"version": "DOMINUS-LIVE-MAP-V29", "target": target, "errors": [{"provider": "live-map", "status": "unavailable", "detail": str(exc)[:300]}]}, status_code=200)

@router.get("/services/url-domain-analyst/api/{section}", response_class=JSONResponse)
async def url_domain_isolated_api(
    request: Request,
    section: str,
    target: str = "",
    limit: int = 500,
    offset: int = 0,
    country: str = "",
    asn: str = "",
    service: str = "",
):
    """Return one investigation section without rendering the complete HTML dossier.

    The attack-surface section supports server-side pagination/filtering so large
    provider datasets remain usable without loading every row into the browser.
    """
    value=(target or "").strip()
    if not value:
        return JSONResponse({"status":"error","error":"target query parameter is required"}, status_code=400)
    try:
        try:
            result=await _analyze_url_domain_cached(value, 'deep')
        except TypeError:
            # Preserve compatibility with older/custom analyzers whose call signature
            # only accepts the target.
            result=analyze_url_domain(value)
        if inspect.isawaitable(result):
            result=await result
    except Exception as exc:
        result={"target":value,"domain":value,"verdict":"unknown","risk_score":0,"url_domain_vnext":{"version":"16.0","provider_error_ledger":[{"stage":"isolated_api","error":str(exc)[:500],"recoverable":True}]}}
    if not isinstance(result, dict):
        result={"target":value,"domain":value,"verdict":"unknown","risk_score":0,"url_domain_vnext":{}}
    v=result.get("url_domain_vnext") if isinstance(result.get("url_domain_vnext"),dict) else {}
    existing_surface = v.get("attack_surface") if isinstance(v.get("attack_surface"), dict) else {}
    if (not existing_surface.get("a_records") and not existing_surface.get("services")) and isinstance(result.get("dnsdumpster"), dict):
        v["attack_surface"] = build_attack_surface(result)
    aliases={
      "overview": result, "geo": v.get("geo_intelligence",{}), "services": v.get("services_banners",{}),
      "security-stack": v.get("security_stack_observables",{}), "workforce": v.get("workforce_intelligence",{}),
      "graph": result.get("graph",{}), "registration": v.get("rdap_lifecycle",result.get("whois_rdap",{})),
      "dns": v.get("dns",result.get("dns",{})), "network": v.get("infrastructure",result.get("network_associations",{})),
      "certs": v.get("certificate_transparency",result.get("certificate_transparency",{})), "osint-deep": v.get("osint_deep",{}),
      "breach": v.get("breach_exposure",result.get("breach_intelligence",{})),
      "attack-surface": v.get("attack_surface",{}),
      "collection-matrix": v.get("collection_matrix",{}),
    }
    data = aliases.get(section,{})
    if section == "attack-surface" and isinstance(data, dict):
        rows = data.get("a_records") if isinstance(data.get("a_records"), list) else []
        def match(row):
            if country and country.lower() not in str(row.get("country") or "").lower(): return False
            if asn and asn.lower() not in str(row.get("asn") or "").lower(): return False
            if service and service.lower() not in " ".join(str(x) for x in (row.get("open_services") or [])).lower(): return False
            return True
        filtered=[row for row in rows if isinstance(row,dict) and match(row)]
        safe_limit=max(1,min(int(limit or 500),10000)); safe_offset=max(0,int(offset or 0))
        payload=dict(data); payload["a_records_page"]=filtered[safe_offset:safe_offset+safe_limit]; payload["pagination"]={"total":len(filtered),"offset":safe_offset,"limit":safe_limit,"has_more":safe_offset+safe_limit < len(filtered)}
        data=payload
    return JSONResponse({"status":"completed","section":section,"target":value,"data":data})


@router.get("/services/url-domain-analyst/api/attack-surface/entity", response_class=JSONResponse)
async def url_domain_attack_surface_entity(request: Request, target: str = "", host: str = "", ip: str = ""):
    value=(target or "").strip()
    if not value:
        return JSONResponse({"status":"error","error":"target query parameter is required"}, status_code=400)
    try:
        result=await _analyze_url_domain_cached(value, 'deep')
    except Exception as exc:
        return JSONResponse({"status":"error","error":str(exc)[:500]}, status_code=502)
    if not isinstance(result,dict): return JSONResponse({"status":"error","error":"analyzer returned invalid result"}, status_code=502)
    v=result.get("url_domain_vnext") if isinstance(result.get("url_domain_vnext"),dict) else {}
    surface=v.get("attack_surface") if isinstance(v.get("attack_surface"),dict) else build_attack_surface(result)
    rows=[x for x in (surface.get("a_records") or []) if isinstance(x,dict)]
    wanted_host=host.strip().lower(); wanted_ip=ip.strip()
    match=next((x for x in rows if (wanted_host and str(x.get("host") or "").lower()==wanted_host) or (wanted_ip and str(x.get("ip") or "")==wanted_ip)), None)
    if not match: return JSONResponse({"status":"not_found","target":value,"host":host,"ip":ip,"matches":0}, status_code=404)
    return JSONResponse({"status":"completed","target":value,"data":build_host_isolate(match)})

@router.get("/services/email-analyst/agent", response_class=JSONResponse)
def email_agent_manifest():
    """Expose the Email Analyst agent/fabric contract without executing connectors."""
    return agent_manifest()


@router.post("/services/email-analyst", response_class=HTMLResponse)
async def guest_email_analysis(request: Request, file: UploadFile = File(...)):
    guest_id = _guest_id(request)
    from phishhunter.db.database import SessionLocal
    try:
        data = await read_upload_limited(file, settings.max_upload_mb * 1024 * 1024)
        filename = validate_upload(file.filename or "email.eml", data, settings.max_upload_mb)
        result = analyze_email_deep(data)
        result["email_fabric"] = connector_fabric()
        result["email_agent_manifest"] = agent_manifest()
        result["enrichment"] = await enrich_result(result, "email")
        db = SessionLocal()
        try:
            return _result_page(request, "email-analyst", result, filename, guest_id, db)
        finally:
            db.close()
    except Exception as exc:
        response = _render(request, "service_error.html", service=SERVICE_CATALOG["email-analyst"], error=str(exc), title="Email Analysis Error")
        return _guest_response(request, response, guest_id)

@router.post("/services/file-analyst", response_class=HTMLResponse)
async def guest_file_analysis(request: Request, file: UploadFile = File(...)):
    guest_id = _guest_id(request)
    from phishhunter.db.database import SessionLocal
    try:
        data = await read_upload_limited(file, settings.max_upload_mb * 1024 * 1024)
        filename = validate_upload(file.filename or "sample.bin", data, settings.max_upload_mb)
        result = analyze_file(filename, data)
        result["enrichment"] = await enrich_result(result, "file")
        db = SessionLocal()
        try:
            return _result_page(request, "file-analyst", result, filename, guest_id, db)
        finally:
            db.close()
    except Exception as exc:
        response = _render(request, "service_error.html", service=SERVICE_CATALOG["file-analyst"], error=str(exc), title="File Analysis Error")
        return _guest_response(request, response, guest_id)

@router.post("/services/pcap-analyst", response_class=HTMLResponse)
async def guest_pcap_analysis(request: Request, file: UploadFile = File(...)):
    guest_id = _guest_id(request)
    from phishhunter.db.database import SessionLocal
    try:
        data = await read_upload_limited(file, settings.max_upload_mb * 1024 * 1024)
        filename = validate_upload(file.filename or "capture.pcap", data, settings.max_upload_mb)
        result = augment_pcap(analyze_pcap(data))
        result["enrichment"] = await enrich_result(result, "pcap")
        db = SessionLocal()
        try:
            return _result_page(request, "pcap-analyst", result, filename, guest_id, db)
        finally:
            db.close()
    except Exception as exc:
        response = _render(request, "service_error.html", service=SERVICE_CATALOG["pcap-analyst"], error=str(exc), title="PCAP Analysis Error")
        return _guest_response(request, response, guest_id)

@router.post("/services/ip-analyst", response_class=HTMLResponse)
async def guest_ip_analysis(request: Request, indicator: str = Form(...)):
    guest_id = _guest_id(request); db = SessionLocal(); value = indicator.strip()
    try:
        result = deep_ip_analysis(value)
        result["enrichment"] = {"status": "provider_optional", "providers": connector_catalog()}
        return _result_page(request, "ip-analyst", result, value, guest_id, db)
    except Exception as exc:
        response = _render(request, "service_error.html", service=SERVICE_CATALOG["ip-analyst"], error=str(exc), title="IP Analysis Error")
        return _guest_response(request, response, guest_id)
    finally: db.close()


@router.post("/services/ioc-analyst", response_class=HTMLResponse)
async def guest_ioc_analysis(request: Request, indicator: str = Form(...)):
    guest_id = _guest_id(request); db = SessionLocal(); value = indicator.strip()
    try:
        result = deep_ioc_analysis(value)
        result["enrichment"] = {"status": "provider_optional", "providers": connector_catalog()}
        return _result_page(request, "ioc-analyst", result, value[:500], guest_id, db)
    except Exception as exc:
        response = _render(request, "service_error.html", service=SERVICE_CATALOG["ioc-analyst"], error=str(exc), title="IOC Analysis Error")
        return _guest_response(request, response, guest_id)
    finally: db.close()


@router.post("/services/malware-analyst", response_class=HTMLResponse)
async def guest_malware_analysis(request: Request, file: UploadFile = File(...)):
    return await _guest_file_specialized(request, file, "malware-analyst", "malware")


@router.post("/services/ransomware-analyst", response_class=HTMLResponse)
async def guest_ransomware_analysis(request: Request, file: UploadFile = File(...)):
    return await _guest_file_specialized(request, file, "ransomware-analyst", "ransomware")


@router.post("/services/phishing-kit-analyst", response_class=HTMLResponse)
async def guest_phishing_kit_analysis(request: Request, file: UploadFile = File(...)):
    return await _guest_file_specialized(request, file, "phishing-kit-analyst", "phishing-kit")


async def _guest_file_specialized(request: Request, file: UploadFile, service_key: str, mode: str) -> HTMLResponse:
    guest_id = _guest_id(request); db = SessionLocal()
    try:
        data = await read_upload_limited(file, settings.max_upload_mb * 1024 * 1024)
        filename = validate_upload(file.filename or "artifact.bin", data, settings.max_upload_mb)
        if mode == "ransomware": result = deep_ransomware_analysis(filename, data)
        elif mode == "phishing-kit": result = deep_phishing_kit_analysis(filename, data)
        else:
            result = analyze_file(filename, data)
            result["analysis_engine"] = {"name": "K4 Malware Deep Static Engine", "version": "10.1"}
            result["static_scope"] = {"hashes": True, "metadata": True, "strings": True, "pe_analysis": True, "runtime_execution": False}
        result["enrichment"] = await enrich_result(result, "file")
        return _result_page(request, service_key, result, filename, guest_id, db)
    except Exception as exc:
        response = _render(request, "service_error.html", service=SERVICE_CATALOG[service_key], error=str(exc), title=f"{SERVICE_CATALOG[service_key]['title']} Error")
        return _guest_response(request, response, guest_id)
    finally: db.close()


@router.post("/services/threat-intelligence", response_class=HTMLResponse)
async def guest_threat_intelligence(request: Request, indicator: str = Form(...)):
    guest_id = _guest_id(request); db = SessionLocal(); value = indicator.strip()
    try:
        result = deep_ioc_analysis(value)
        result["intelligence"] = {"connector_catalog": connector_catalog(), "configured_provider_execution": False, "attribution": "not asserted"}
        result["enrichment"] = {"status": "configure_connectors_for_live_lookup", "providers": connector_catalog()}
        return _result_page(request, "threat-intelligence", result, value[:500], guest_id, db)
    except Exception as exc:
        response = _render(request, "service_error.html", service=SERVICE_CATALOG["threat-intelligence"], error=str(exc), title="Threat Intelligence Error")
        return _guest_response(request, response, guest_id)
    finally: db.close()


@router.post("/services/sandbox", response_class=HTMLResponse)
async def guest_sandbox(request: Request, sha256: str = Form(...)):
    guest_id = _guest_id(request); db = SessionLocal(); value = sha256.strip().lower()
    try:
        result = sandbox_manifest(value)
        return _result_page(request, "sandbox", result, value, guest_id, db)
    except Exception as exc:
        response = _render(request, "service_error.html", service=SERVICE_CATALOG["sandbox"], error=str(exc), title="Sandbox Error")
        return _guest_response(request, response, guest_id)
    finally: db.close()


@router.post("/services/reports", response_class=HTMLResponse)
async def guest_reports(request: Request, analysis_json: str = Form(...), title: str = Form("Cyber-Phish-k4 Analyst Report")):
    guest_id = _guest_id(request); db = SessionLocal()
    try:
        result = json.loads(analysis_json)
        if not isinstance(result, dict): raise ValueError("Analysis JSON must contain an object")
        result = normalize_result(result)
        result["report"] = {"title": title[:255], "formats": ["pdf", "html", "json", "markdown", "stix", "txt", "ioc-csv", "connections-csv", "bundle-zip"], "json": report_json(title, result), "markdown": report_markdown(title, result), "html": report_html(title, result), "stix": report_stix(title, result), "txt": report_text(title, result)}
        return _result_page(request, "reports", result, title[:255], guest_id, db)
    except Exception as exc:
        response = _render(request, "service_error.html", service=SERVICE_CATALOG["reports"], error=str(exc), title="Report Error")
        return _guest_response(request, response, guest_id)
    finally: db.close()


@router.post("/services/reports/export")
async def guest_report_export(analysis_json: str = Form(...), title: str = Form("Cyber-Phish-k4 Analyst Report"), format: str = Form("pdf")):
    try:
        result = json.loads(analysis_json)
        if not isinstance(result, dict):
            raise ValueError("Analysis JSON must contain an object")
        result = normalize_result(result)
        safe_title = title[:120].strip() or "k4_report"
        key = format.lower().strip()
        if key == "pdf":
            payload, media, ext = report_pdf(safe_title, result), "application/pdf", "pdf"
        elif key in {"bundle", "bundle-zip", "zip"}:
            payload, media, ext = report_bundle(safe_title, result), "application/zip", "zip"
        elif key == "ioc-csv":
            payload, media, ext = report_ioc_csv(result).encode(), "text/csv; charset=utf-8", "iocs.csv"
        elif key == "connections-csv":
            payload, media, ext = report_connections_csv(result).encode(), "text/csv; charset=utf-8", "connections.csv"
        else:
            payload, media, ext = report_export(key, safe_title, result)
        filename = "".join(c if c.isalnum() or c in "-_" else "_" for c in safe_title).strip("_") or "k4_report"
        return Response(content=payload, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}.{ext}"'})
    except Exception as exc:
        return Response(content=json.dumps({"error": str(exc)}), media_type="application/json", status_code=400)


def _workspace_result(request: Request, key: str, workspace_type: str, title: str, data: dict, guest_id: str, db: Session):
    row = GuestWorkspace(guest_id=guest_id, workspace_type=workspace_type, title=title[:255], data=normalize_result(data))
    db.add(row); db.commit(); db.refresh(row)
    result={"analysis_engine":{"name":f"K4 {SERVICE_CATALOG[key]['title']} Engine","version":"10.1"},"verdict":"tracked","risk_score":0,"workspace":{"id":row.id,"type":workspace_type,"title":row.title,"data":row.data},"evidence":data.get("evidence",[]),"iocs":data.get("iocs",{}),"mitre_techniques":data.get("mitre_techniques",[])}
    return _result_page(request,key,result,title,guest_id,db)


@router.post("/services/cases", response_class=HTMLResponse)
async def guest_cases(request: Request, title: str = Form(...), priority: str = Form("medium"), notes: str = Form("")):
    guest_id=_guest_id(request); db=SessionLocal()
    try: return _workspace_result(request,"cases","case",title,{"priority":priority,"notes":notes[:10000],"status":"open"},guest_id,db)
    except Exception as exc:
        response=_render(request,"service_error.html",service=SERVICE_CATALOG["cases"],error=str(exc),title="Case Error"); return _guest_response(request,response,guest_id)
    finally: db.close()


@router.post("/services/campaigns", response_class=HTMLResponse)
async def guest_campaigns(request: Request, title: str = Form(...), indicators: str = Form("")):
    guest_id=_guest_id(request); db=SessionLocal()
    try:
        parsed=deep_ioc_analysis(indicators or title)
        return _workspace_result(request,"campaigns","campaign",title,{"status":"open","iocs":parsed.get("iocs",{}),"indicator_counts":parsed.get("counts",{})},guest_id,db)
    except Exception as exc:
        response=_render(request,"service_error.html",service=SERVICE_CATALOG["campaigns"],error=str(exc),title="Campaign Error"); return _guest_response(request,response,guest_id)
    finally: db.close()


@router.post("/services/actors", response_class=HTMLResponse)
async def guest_actors(request: Request, name: str = Form(...), evidence: str = Form("")):
    guest_id=_guest_id(request); db=SessionLocal()
    try:
        parsed=deep_ioc_analysis(evidence or name)
        return _workspace_result(request,"actors","actor",name,{"status":"observed","evidence_text":evidence[:10000],"iocs":parsed.get("iocs",{}),"attribution":"withheld pending independent corroboration"},guest_id,db)
    except Exception as exc:
        response=_render(request,"service_error.html",service=SERVICE_CATALOG["actors"],error=str(exc),title="Actor Workspace Error"); return _guest_response(request,response,guest_id)
    finally: db.close()


@router.post("/services/graph", response_class=HTMLResponse)
async def guest_graph(request: Request, indicator: str = Form(...)):
    guest_id=_guest_id(request); db=SessionLocal()
    try:
        parsed=deep_ioc_analysis(indicator); parsed["graph"]=build_graph(parsed); parsed["enrichment"]={"status":"not_requested","providers":[]}
        return _result_page(request,"graph",parsed,indicator[:500],guest_id,db)
    except Exception as exc:
        response=_render(request,"service_error.html",service=SERVICE_CATALOG["graph"],error=str(exc),title="Graph Error"); return _guest_response(request,response,guest_id)
    finally: db.close()


@router.post("/services/feeds", response_class=HTMLResponse)
async def guest_feeds(request: Request, source: str = Form("uploaded-feed"), feed_text: str = Form(...)):
    guest_id=_guest_id(request); db=SessionLocal()
    try:
        result=deep_feed_analysis(source,feed_text); result["enrichment"]={"status":"not_requested","providers":[]}
        return _result_page(request,"feeds",result,source,guest_id,db)
    except Exception as exc:
        response=_render(request,"service_error.html",service=SERVICE_CATALOG["feeds"],error=str(exc),title="Feed Error"); return _guest_response(request,response,guest_id)
    finally: db.close()


@router.get("/services/threat-intelligence/providers", response_class=HTMLResponse)
def providers_fragment(request: Request):
    providers = connector_catalog()
    return _render(request, "providers_fragment.html", providers=providers)
