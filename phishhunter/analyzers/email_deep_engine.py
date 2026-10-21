from __future__ import annotations

"""Ultra-deep, evidence-first email investigation engine.

This module is intentionally isolated to the Email Analyst service.  It performs
static inspection and produces auditable observations; it never sends email,
changes a tenant, blocks infrastructure, or detonates attachments.
"""

import base64
import binascii
import hashlib
import json
import re
import shutil
import subprocess
import zipfile
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from html import unescape
from io import BytesIO
from pathlib import PurePosixPath
from urllib.parse import parse_qs, unquote, urlparse

try:
    from bs4 import BeautifulSoup
except Exception:  # pragma: no cover
    BeautifulSoup = None

from phishhunter_common.hash import hash_bytes
from phishhunter_common.ioc import extract_iocs
from phishhunter.analyzers.email_analyzer import analyze_email

SAFE_LINK_PATTERNS = (
    "safelinks.protection.outlook.com",
    "urldefense.com",
    "urldefense.proofpoint.com",
    "mimecast.com",
    "clicktime.symantec.com",
    "barracudanetworks.com",
)
DANGEROUS_SCHEMES = ("javascript:", "data:", "vbscript:")

ATTACK_MAP = {
    "credential_form": ("T1566.002", "Spearphishing Link"),
    "attachment": ("T1566.001", "Spearphishing Attachment"),
    "service": ("T1566.003", "Spearphishing via Service"),
    "credential_harvest": ("T1056.002", "Input Capture: GUI Input Capture"),
    "html_smuggling": ("T1027.006", "Obfuscated/Compressed Files and Information: HTML Smuggling"),
    "link_obfuscation": ("T1027", "Obfuscated Files or Information"),
    "web_protocol": ("T1071.001", "Web Protocols"),
}


def _safe_json(value):
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def _domain(value: str) -> str:
    m = re.search(r"@([A-Za-z0-9._-]+)", value or "")
    return m.group(1).lower().rstrip(".") if m else ""


def _decode_bytes(part) -> bytes:
    try:
        return part.get_payload(decode=True) or b""
    except Exception:
        payload = part.get_payload()
        return payload.encode(errors="replace") if isinstance(payload, str) else b""


def _magic(data: bytes) -> tuple[str, str]:
    sig = data[:16]
    table = [
        (b"MZ", "PE/Windows executable"),
        (b"\x7fELF", "ELF executable"),
        (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP/container (OOXML/JAR/ZIP)"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2/Compound File"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF8", "GIF image"),
        (b"RIFF", "RIFF container"),
        (b"SQLite format 3", "SQLite database"),
    ]
    for prefix, label in table:
        if sig.startswith(prefix):
            return prefix.hex(), label
    return sig[:8].hex(), "unknown"


def _decode_wrapper(url: str) -> dict:
    original = url
    candidate = unescape(url.strip())
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    decoded = None
    mechanism = None
    qs = parse_qs(parsed.query)
    for key in ("url", "u", "target", "dest", "destination", "redirect", "r"):
        if qs.get(key):
            decoded = unquote(qs[key][0])
            mechanism = f"query:{key}"
            break
    if not decoded and "urldefense.com" in host:
        m = re.search(r"__https?://(.+?)(?:__|$)", candidate)
        if m:
            decoded = "https://" + m.group(1)
            mechanism = "proofpoint-path"
    if not decoded and "mimecast.com" in host:
        m = re.search(r"/s/(?:[^/]+/)?(.+)$", parsed.path)
        if m:
            decoded = unquote(m.group(1))
            mechanism = "mimecast-path"
    if not decoded and "barracudanetworks.com" in host:
        for key in ("u", "url"):
            if qs.get(key):
                decoded = unquote(qs[key][0])
                mechanism = f"barracuda:{key}"
                break
    return {
        "original": original[:2000],
        "wrapper_detected": bool(decoded),
        "mechanism": mechanism,
        "destination": decoded[:2000] if decoded else None,
        "destination_domain": (urlparse(decoded).hostname or "").lower() if decoded else None,
    }


def _psychology(text: str) -> dict:
    lower = text.lower()
    buckets = {
        "urgency": ["urgent", "immediately", "today", "expires", "within 24 hours", "act now"],
        "fear": ["suspended", "locked", "fraud", "breach", "unauthorized", "security alert", "terminate"],
        "authority": ["ceo", "cfo", "director", "administrator", "microsoft", "bank", "security team", "hr"],
        "greed": ["refund", "bonus", "gift", "prize", "reward", "invoice", "payment"],
        "curiosity": ["document", "confidential", "secret", "shared file", "review attachment", "see details"],
    }
    result = {}
    for name, terms in buckets.items():
        hits = [t for t in terms if t in lower]
        score = min(10, 1 + len(hits) * 2) if hits else 1
        result[name] = {"score": score, "terms": hits, "method": "deterministic lexical evidence"}
    return result


def _header_graph(msg) -> dict:
    hops = []
    received = msg.get_all("Received", [])
    for idx, raw in enumerate(received, 1):
        raw_s = str(raw)
        timestamp = None
        epoch = None
        m = re.search(r";\s*(.+)$", raw_s, re.S)
        if m:
            try:
                dt = parsedate_to_datetime(m.group(1).strip())
                timestamp = dt.isoformat()
                epoch = dt.timestamp()
            except Exception:
                pass
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_s)
        from_host = None
        by_host = None
        fm = re.search(r"\bfrom\s+([^\s(]+)", raw_s, re.I)
        bm = re.search(r"\bby\s+([^\s;]+)", raw_s, re.I)
        if fm:
            from_host = fm.group(1).strip("[]")
        if bm:
            by_host = bm.group(1).strip("[]")
        hops.append({
            "hop": idx,
            "from": from_host,
            "by": by_host,
            "ips": ip_matches,
            "timestamp": timestamp,
            "epoch": epoch,
            "raw": raw_s[:5000],
        })
    ordered = sorted(hops, key=lambda x: x["epoch"] if x["epoch"] is not None else float("inf"))
    edges = []
    latencies = []
    for a, b in zip(ordered, ordered[1:]):
        latency = None
        if a["epoch"] is not None and b["epoch"] is not None:
            latency = round(max(0, b["epoch"] - a["epoch"]) * 1000, 3)
            latencies.append(latency)
        edges.append({"from_hop": a["hop"], "to_hop": b["hop"], "latency_ms": latency})
    return {
        "nodes": ordered,
        "edges": edges,
        "hop_count": len(ordered),
        "latency_ms": latencies,
        "max_latency_ms": max(latencies) if latencies else None,
        "latency_anomalies": [e for e in edges if e["latency_ms"] is not None and e["latency_ms"] >= 3600000],
        "method": "RFC 5322 Received-chain evidence; timestamps are untrusted message evidence",
    }


def _header_forgery(msg, graph: dict) -> list[dict]:
    findings = []
    internal_markers = []
    for name, value in msg.items():
        lname = str(name).lower()
        if lname.startswith("x-ms-exchange-organization-") or lname in {
            "x-originating-ip", "x-authenticated-user", "x-authentication-warning", "x-google-original-from",
        }:
            internal_markers.append({"header": str(name), "value": str(value)[:1000]})
    external_ips = [ip for node in graph["nodes"] for ip in node["ips"]]
    if internal_markers and external_ips:
        for marker in internal_markers:
            value = marker["value"].lower()
            if "internal" in value or "authenticated" in value:
                findings.append({
                    "type": "internal-header-contradiction",
                    "header": marker["header"],
                    "evidence": marker["value"],
                    "confidence": 72,
                    "interpretation": "An internal-looking header is present alongside externally supplied Received-chain evidence; this can indicate forged or relayed metadata and requires mail-server telemetry for confirmation.",
                })
    return findings


def _dom_analysis(html_body: str) -> dict:
    if not html_body:
        return {"available": False, "reason": "no HTML body"}
    if BeautifulSoup is None:
        return {"available": False, "reason": "beautifulsoup4 unavailable"}
    soup = BeautifulSoup(html_body, "html.parser")
    iframes = soup.find_all("iframe")
    invisible_iframes = []
    for tag in iframes:
        style = (tag.get("style") or "").lower()
        attrs = " ".join(f"{k}={v}" for k, v in tag.attrs.items()).lower()
        if tag.get("width") in {"0", 0} or tag.get("height") in {"0", 0} or "display:none" in style or "visibility:hidden" in style or "opacity:0" in style:
            invisible_iframes.append(str(tag)[:1000])
    styles = " ".join(str(x) for x in soup.find_all("style"))
    scripts = [str(x)[:4000] for x in soup.find_all("script")]
    canvas = soup.find_all("canvas")
    forms = []
    for form in soup.find_all("form"):
        forms.append({
            "action": form.get("action", ""),
            "method": form.get("method", "get").lower(),
            "inputs": [
                {"name": i.get("name"), "type": i.get("type", "text"), "autocomplete": i.get("autocomplete")}
                for i in form.find_all("input")[:100]
            ],
        })
    css_cloak_patterns = re.findall(r"(?i)(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|color\s*:\s*(?:#fff(?:fff)?|white))", styles + html_body)
    external_resources = []
    for tag in soup.find_all(["img", "script", "link", "iframe"]):
        for attr in ("src", "href"):
            if tag.get(attr):
                external_resources.append(tag.get(attr)[:1000])
    return {
        "available": True,
        "title": soup.title.get_text(" ", strip=True)[:300] if soup.title else "",
        "text_length": len(soup.get_text(" ", strip=True)),
        "tag_counts": dict(Counter(t.name for t in soup.find_all())),
        "invisible_iframes": invisible_iframes[:50],
        "iframe_count": len(iframes),
        "canvas_count": len(canvas),
        "canvas_fingerprint_signals": ["canvas element present"] if canvas else [],
        "css_cloaking_hits": sorted(set(css_cloak_patterns))[:50],
        "script_count": len(scripts),
        "javascript_indicators": [
            "eval(" if "eval(" in "\n".join(scripts) else None,
            "atob(" if "atob(" in "\n".join(scripts) else None,
            "document.write" if "document.write" in "\n".join(scripts).lower() else None,
            "location assignment" if re.search(r"(?i)location\s*=", "\n".join(scripts)) else None,
        ],
        "forms": forms[:100],
        "external_resources": external_resources[:500],
    }


def _embedded_images(html_body: str) -> dict:
    images = []
    for idx, m in enumerate(re.finditer(r"data:image/([a-zA-Z0-9.+-]+);base64,([A-Za-z0-9+/=\r\n]+)", html_body), 1):
        mime = m.group(1).lower()
        blob = re.sub(r"\s+", "", m.group(2))
        try:
            raw = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        magic, kind = _magic(raw)
        images.append({"index": idx, "mime": mime, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "magic": magic, "kind": kind, "ocr": {"status": "not-run", "reason": "OCR is opt-in and requires a local Tesseract deployment"}})
    return {"count": len(images), "images": images[:100]}


def _attachment_deep(msg) -> list[dict]:
    results = []
    for index, part in enumerate(msg.walk()):
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        if not filename and disposition != "attachment":
            continue
        data = _decode_bytes(part)
        magic_hex, true_type = _magic(data)
        lower_name = (filename or "unnamed").lower()
        ext = PurePosixPath(lower_name).suffix
        extension_mismatch = bool(ext and true_type != "unknown" and ((ext in {".exe", ".scr", ".dll", ".com", ".msi"} and "executable" not in true_type.lower()) or (ext == ".pdf" and "pdf" not in true_type.lower())))
        ole = data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
        zip_container = data.startswith(b"PK\x03\x04")
        zip_entries = []
        html_smuggling = False
        vba_signals = []
        archive_ratio = None
        if zip_container:
            try:
                with zipfile.ZipFile(BytesIO(data)) as zf:
                    infos = zf.infolist()
                    zip_entries = [i.filename for i in infos[:200]]
                    uncompressed = sum(i.file_size for i in infos)
                    archive_ratio = round(uncompressed / max(1, len(data)), 2)
                    if any("vbaproject.bin" in n.lower() for n in zip_entries):
                        vba_signals.append("OOXML VBA project present")
                    for name in zip_entries:
                        if name.lower().endswith((".html", ".htm", ".js")):
                            try:
                                raw = zf.read(name)[:2_000_000]
                                txt = raw.decode("utf-8", errors="ignore")
                                if len(re.findall(r"(?i)(?:atob\(|base64|Uint8Array|Blob\(|msSaveOrOpenBlob|download)", txt)) >= 2:
                                    html_smuggling = True
                            except Exception:
                                pass
            except (zipfile.BadZipFile, RuntimeError, ValueError):
                pass
        if lower_name.endswith((".html", ".htm", ".js")):
            txt = data[:5_000_000].decode("utf-8", errors="ignore")
            html_smuggling = html_smuggling or (len(re.findall(r"(?i)(?:base64|atob\(|Uint8Array|Blob\(|download)", txt)) >= 3)
        if ole:
            sample = data[:5_000_000].decode("latin1", errors="ignore").lower()
            for token in ("vba", "olevba", "shell", "wscript.shell", "urldownloadtofile", "powershell", "autoopen", "document_open"):
                if token in sample:
                    vba_signals.append(token)
        results.append({
            "index": index,
            "filename": filename or "unnamed",
            "content_type": part.get_content_type(),
            "size": len(data),
            "sha256": hash_bytes(data)["sha256"] if data else None,
            "magic": magic_hex,
            "true_type": true_type,
            "extension": ext,
            "extension_mismatch": extension_mismatch,
            "ole2": ole,
            "vba_signals": sorted(set(vba_signals)),
            "zip_entries": zip_entries,
            "archive_expansion_ratio": archive_ratio,
            "html_smuggling": html_smuggling,
            "dynamic_execution": "not performed",
        })
    return results


def _phishing_kit_fingerprint(dom: dict, html_body: str) -> list[dict]:
    if not dom.get("available"):
        return []
    text = html_body.lower()
    signatures = [
        ("Evilginx-like", ["auth", "session", "redirect_uri", "proxy"], "reverse-proxy credential interception pattern; not attribution"),
        ("Modlishka-like", ["phishlet", "target_hosts", "proxy_hosts"], "reverse-proxy configuration markers; not attribution"),
        ("Muraena-like", ["muraena", "phishlet"], "tool-specific marker; not attribution"),
        ("Credential-harvest kit", ["password", "username", "login", "sign in"], "credential form language and input fields"),
    ]
    findings = []
    for name, tokens, reason in signatures:
        hits = [t for t in tokens if t in text]
        if len(hits) >= 2:
            findings.append({"label": name, "matched": hits, "confidence": min(90, 45 + 10 * len(hits)), "note": reason})
    return findings


def _frameworks(result: dict) -> dict:
    techniques = {str(x.get("id")): x for x in result.get("mitre_techniques", []) if isinstance(x, dict)}
    if result.get("forms"):
        techniques.setdefault("T1566.002", {"id": "T1566.002", "name": "Spearphishing Link", "evidence_count": 1})
    if result.get("attachments"):
        techniques.setdefault("T1566.001", {"id": "T1566.001", "name": "Spearphishing Attachment", "evidence_count": len(result["attachments"])})
    if any(a.get("html_smuggling") for a in result.get("deep_attachments", [])):
        techniques.setdefault("T1027.006", {"id": "T1027.006", "name": "HTML Smuggling", "evidence_count": 1})
    if any(f.get("password_field") for f in result.get("forms", [])):
        techniques.setdefault("T1056.002", {"id": "T1056.002", "name": "Input Capture: GUI Input Capture", "evidence_count": 1})
    return {
        "mitre_attack": sorted(techniques.values(), key=lambda x: x["id"]),
        "cyber_kill_chain": [
            {"phase": "Delivery", "evidence": "Email artifact received"},
            {"phase": "Exploitation", "evidence": "Credential form / active content signals" if result.get("forms") or result.get("deep_html", {}).get("script_count") else "No direct exploitation evidence"},
            {"phase": "Actions on Objectives", "evidence": "Credential harvesting or attachment delivery signals" if result.get("risk_score", 0) >= 55 else "Not established from static email evidence"},
        ],
        "diamond_model": {
            "adversary": {"value": None, "confidence": 0, "status": "withheld"},
            "victim": {"value": result.get("to") or None, "confidence": 0, "status": "evidence-only"},
            "infrastructure": sorted(set([x.get("domain") for x in result.get("links", []) if x.get("domain")] + [x.get("destination_domain") for x in result.get("safe_link_decodings", []) if x.get("destination_domain")])),
            "capability": sorted(set(x.get("label") for x in result.get("phishing_kit_fingerprints", []) if x.get("label"))),
        },
        "mitre_d3fend": [
            {"control": "D3-ERA", "name": "Email Filtering", "status": "recommended", "reason": "Use observed sender/link/attachment indicators in gateway rules."},
            {"control": "D3-CFA", "name": "Credential Filtering", "status": "recommended", "reason": "Credential collection indicators were observed." if any(f.get("password_field") for f in result.get("forms", [])) else "No password form observed; keep control available."},
            {"control": "D3-HPA", "name": "Host Process Analysis", "status": "follow-up", "reason": "Required only if an attachment was opened or executed; this engine does not execute it."},
        ],
    }


def _agent_plan(result: dict) -> dict:
    pivots = []
    if result.get("iocs", {}).get("urls"): pivots.append("Inspect extracted URLs in a configured URL reputation/sandbox connector")
    if result.get("iocs", {}).get("domains"): pivots.append("Correlate domains across passive DNS, WHOIS and threat-intelligence sources")
    if result.get("iocs", {}).get("ips"): pivots.append("Check IP infrastructure, ASN, DNS history and benign-noise context")
    if result.get("deep_attachments"): pivots.append("Submit attachment hashes to configured malware intelligence; detonate only in an isolated sandbox")
    if result.get("auth", {}).get("dmarc_result") == "fail": pivots.append("Review DMARC alignment and mail-gateway telemetry for the sender")
    if result.get("forms"): pivots.append("Review credential-collection destinations and affected recipients")
    if not pivots: pivots.append("Review raw headers, authentication evidence and message provenance before disposition")
    return {
        "name": "K4 Email Investigation Agent",
        "mode": "evidence-first deterministic agent",
        "status": "ready",
        "objective": "Turn email evidence into an ordered, explainable investigation plan.",
        "next_pivots": pivots,
        "recommended_sequence": [
            "Validate raw MIME and header provenance",
            "Review authentication alignment and hop chronology",
            "Inspect HTML/DOM and link transformations",
            "Review attachment type, hashes and active-content indicators",
            "Enrich only through configured connectors",
            "Correlate with internal telemetry before containment",
            "Export evidence-backed findings and preserve uncertainty",
        ],
        "guardrails": [
            "No automatic mailbox deletion or firewall changes",
            "No attachment execution on the application host",
            "No actor attribution from a single email artifact",
            "External intelligence is marked unavailable when no connector is configured",
        ],
    }



def _mime_inventory(msg) -> list[dict]:
    parts=[]
    for index, part in enumerate(msg.walk()):
        if part.is_multipart():
            continue
        data=_decode_bytes(part)
        parts.append({
            "index": index,
            "content_type": part.get_content_type(),
            "disposition": part.get_content_disposition(),
            "filename": part.get_filename(),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest() if data else None,
        })
    return parts


def _signing_detection(msg) -> dict:
    headers={str(k).lower():str(v) for k,v in msg.items()}
    return {
        "smime": any(k in headers for k in ("content-type",)) and "multipart/signed" in headers.get("content-type", "").lower(),
        "pgp": "application/pgp-signature" in headers.get("content-type", "").lower(),
        "dkim": bool(msg.get("DKIM-Signature")),
    }


def _risk_breakdown(base: dict, graph: dict, deep_html: dict, safe_links: list, kit: list, attachments: list, header_forgery: list, psych: dict) -> list[dict]:
    checks=[
        ("Sender/header inconsistency", bool(base.get("mismatches") or header_forgery), 15),
        ("Authentication failure evidence", any(base.get("auth",{}).get(k)=="fail" for k in ("spf_result","dkim_result","dmarc_result")), 12),
        ("Routing delay anomaly", bool(graph.get("latency_anomalies")), 10),
        ("HTML cloaking / hidden content", bool(deep_html.get("invisible_iframes") or deep_html.get("css_cloaking_hits")), 10),
        ("Security gateway wrapper", bool(safe_links), 8),
        ("Phishing-kit pattern", bool(kit), 12),
        ("Suspicious attachment", any(a.get("extension_mismatch") or a.get("html_smuggling") or a.get("vba_signals") for a in attachments), 15),
        ("High social-engineering pressure", any(v.get("score",0)>=7 for v in psych.values()), 5),
        ("Credential collection form", bool(base.get("forms")), 15),
    ]
    return [{"signal":n,"triggered":bool(t),"weight":w,"interpretation":"Observed in static evidence" if t else "Not observed by local rule"} for n,t,w in checks]



def _address_identity(value: str) -> dict:
    from email.utils import getaddresses
    pairs=getaddresses([value or ""])
    display, address = pairs[0] if pairs else ("", "")
    domain=address.split("@",1)[1].lower().rstrip(".") if "@" in address else ""
    labels=domain.split(".") if domain else []
    unicode_domain=domain.encode("ascii", errors="ignore").decode() if domain else ""
    idn=any(label.startswith("xn--") for label in labels)
    non_ascii=any(ord(ch)>127 for ch in (domain or ""))
    return {"display_name":display,"address":address,"domain":domain,"idn_punycode":idn,"unicode_domain":non_ascii,"local_domain_ascii":unicode_domain}


def _header_inventory_detail(msg) -> dict:
    headers=[]
    x_headers=[]
    for name,value in msg.items():
        item={"name":str(name),"value":str(value)[:4000]}
        headers.append(item)
        if str(name).lower().startswith("x-"):
            x_headers.append(item)
    return {"count":len(headers),"headers":headers,"x_headers":x_headers}

def analyze_email_deep(data: bytes) -> dict:
    base = analyze_email(data)
    msg = BytesParser(policy=policy.default).parsebytes(data)
    text_parts = []
    html_parts = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = _decode_bytes(part)
        if part.get_content_type() == "text/plain":
            text_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
        elif part.get_content_type() == "text/html":
            html_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
    text = "\n".join(text_parts)
    html_body = "\n".join(html_parts)

    deep = dict(base)
    graph = _header_graph(msg)
    deep_html = _dom_analysis(html_body)
    deep_attachments = _attachment_deep(msg)
    safe_links = [_decode_wrapper(x.get("href", "")) for x in base.get("links", []) if any(p in x.get("href", "").lower() for p in SAFE_LINK_PATTERNS)]
    psych = _psychology("\n".join([base.get("subject", ""), base.get("from", ""), text, html_body]))
    header_forgery = _header_forgery(msg, graph)
    embedded = _embedded_images(html_body)
    kit = _phishing_kit_fingerprint(deep_html, html_body)
    mime_parts = _mime_inventory(msg)
    signing_detection = _signing_detection(msg)
    sender_identity = {"from": _address_identity(str(msg.get("From", ""))), "reply_to": _address_identity(str(msg.get("Reply-To", ""))), "return_path": _address_identity(str(msg.get("Return-Path", ""))), "message_id": _address_identity(str(msg.get("Message-ID", "")))}
    header_detail = _header_inventory_detail(msg)

    score = int(base.get("risk_score", 0) or 0)
    score += min(12, len(header_forgery) * 8)
    score += min(10, len(graph.get("latency_anomalies", [])) * 5)
    score += min(10, len(deep_html.get("invisible_iframes", [])) * 5)
    score += min(8, len(deep_html.get("css_cloaking_hits", [])) * 2)
    score += min(12, len(safe_links) * 4)
    score += min(15, len(kit) * 5)
    score += min(15, sum(1 for x in deep_attachments if x.get("extension_mismatch") or x.get("html_smuggling") or x.get("vba_signals")))
    if any(v["score"] >= 7 for v in psych.values()):
        score += 5
    score = min(100, score)

    deep["mime_parts"] = mime_parts
    deep["signing_detection"] = signing_detection
    deep["sender_identity_analysis"] = sender_identity
    deep["header_detail"] = header_detail
    deep["risk_breakdown"] = _risk_breakdown(base, graph, deep_html, safe_links, kit, deep_attachments, header_forgery, psych)
    deep["to"] = ", ".join(str(x) for x in msg.get_all("To", []))[:5000]
    deep["cc"] = ", ".join(str(x) for x in msg.get_all("Cc", []))[:5000]
    deep["header_graph"] = graph
    deep["header_forgery_findings"] = header_forgery
    deep["deep_html"] = deep_html
    deep["embedded_images"] = embedded
    deep["deep_attachments"] = deep_attachments
    deep["safe_link_decodings"] = safe_links
    deep["phishing_kit_fingerprints"] = kit
    deep["psychological_pressure"] = psych
    deep["timezone_analysis"] = {
        "date_header": msg.get("Date"),
        "status": "partial",
        "note": "Date timezone is parsed when present. GeoIP cross-check requires a configured GeoIP/intelligence connector; no location is inferred locally.",
    }
    deep["framework_mapping"] = _frameworks(deep)
    deep["agent"] = _agent_plan(deep)
    deep["risk_score"] = score
    deep["verdict"] = "phishing-likely" if score >= 55 else "suspicious" if score >= 25 else "low-risk"
    deep["analysis_engine"] = {
        "name": "Cyber-Phish-k4 Ultra-Deep Email Engine",
        "version": "3.0",
        "layers": ["RFC5322/MIME", "header graph", "DOM/NLP", "URL wrapper decoding", "attachment magic/OLE/HTML smuggling", "framework mapping", "agentic triage"],
        "execution": "static-only",
    }
    return deep
