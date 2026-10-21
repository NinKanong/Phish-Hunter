from __future__ import annotations

from datetime import datetime
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
import html
import re
from urllib.parse import urlparse

from phishhunter_common.hash import hash_bytes
from phishhunter_common.ioc import extract_iocs
from phishhunter.analysis.correlation import correlate_evidence
from phishhunter.utils.analysis import behavior_findings
from phishhunter.mitre import attribution_guardrail

URGENCY = {
    "urgent": 6,
    "immediately": 7,
    "verify your account": 12,
    "password expires": 12,
    "suspended": 10,
    "payment": 6,
    "gift card": 8,
    "wire transfer": 10,
    "login": 5,
    "security alert": 8,
    "invoice": 4,
    "action required": 8,
    "unusual sign-in": 10,
    "security notice": 6,
}
CREDENTIAL_TERMS = (
    "password",
    "otp",
    "one-time code",
    "sign in",
    "verify",
    "credential",
    "login",
    "authentication",
    "security code",
    "passcode",
)
DANGEROUS_ATTACHMENT_RE = re.compile(
    r"(?i)\.(exe|dll|sys|scr|cpl|com|pif|js|jse|vbs|vbe|ps1|psm1|hta|lnk|iso|img|msi|bat|cmd|reg|url|jar|class)$"
)
TRACKING_IMAGE_RE = re.compile(r"(?i)<img\b[^>]*\b(?:width|height)\s*=\s*[\"']?1[\"']?[^>]*>")


def _decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def _domain(value: str) -> str:
    addresses = getaddresses([value])
    if not addresses:
        return ""
    address = addresses[0][1].lower()
    return address.split("@", 1)[1].rstrip(".") if "@" in address else ""


def _extract_body(msg) -> tuple[str, str, list[dict]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict] = []
    for index, part in enumerate(msg.walk()):
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        content_type = part.get_content_type().lower()
        disposition = (part.get_content_disposition() or "").lower()
        filename = _decode(part.get_filename()) or None
        if disposition == "attachment" or filename:
            attachments.append(
                {
                    "index": index,
                    "filename": filename or "unnamed",
                    "content_type": content_type,
                    "content_disposition": disposition,
                    "size": len(payload),
                    "sha256": hash_bytes(payload)["sha256"] if payload else None,
                    "dangerous_extension": bool(DANGEROUS_ATTACHMENT_RE.search(filename or "")),
                    "is_archive": (filename or "").lower().endswith((".zip", ".7z", ".rar", ".iso")),
                }
            )
            continue
        try:
            decoded = part.get_content()
        except Exception:
            decoded = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if content_type == "text/plain":
            text_parts.append(str(decoded))
        elif content_type == "text/html":
            html_parts.append(str(decoded))
    return "\n".join(text_parts), "\n".join(html_parts), attachments


def _link_analysis(html_body: str) -> dict:
    links: list[dict] = []
    for match in re.finditer(r"<a\b[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", html_body, re.I | re.S):
        href = html.unescape(match.group(1).strip())
        visible = re.sub(r"<[^>]+>", " ", match.group(2))
        visible = re.sub(r"\s+", " ", html.unescape(visible)).strip()
        try:
            href_domain = (urlparse(href).hostname or "").lower()
        except ValueError:
            href_domain = ""
        try:
            visible_domain = (urlparse(visible).hostname or "").lower() if visible.startswith(("http://", "https://")) else ""
        except ValueError:
            visible_domain = ""
        links.append(
            {
                "href": href[:2000],
                "domain": href_domain,
                "visible_text": visible[:240],
                "visible_domain": visible_domain,
                "domain_mismatch": bool(visible_domain and href_domain and visible_domain != href_domain),
                "javascript_scheme": href.lower().startswith("javascript:"),
                "data_scheme": href.lower().startswith("data:"),
            }
        )
    tracking_pixels = len(TRACKING_IMAGE_RE.findall(html_body))
    hidden_text = bool(
        re.search(
            r"(?i)(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|color\s*:\s*(?:white|#fff(?:fff)?)|font-size\s*:\s*0)",
            html_body,
        )
    )
    forms = []
    for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html_body, re.I | re.S):
        attrs, form_body = match.groups()
        action_match = re.search(r"action\s*=\s*[\"']([^\"']+)", attrs, re.I)
        method_match = re.search(r"method\s*=\s*[\"']([^\"']+)", attrs, re.I)
        fields = re.findall(r"<input\b[^>]*name=[\"']?([^\s\"'>]+)[\"']?", form_body, re.I)
        forms.append(
            {
                "action": html.unescape(action_match.group(1)) if action_match else "",
                "method": (method_match.group(1).lower() if method_match else "get"),
                "fields": fields[:50],
                "password_field": any(field.lower() in {"password", "passwd", "pass", "pwd"} for field in fields),
            }
        )
    return {
        "links": links[:500],
        "hidden_text": hidden_text,
        "tracking_pixels": tracking_pixels,
        "forms": forms[:100],
    }


def _received_timeline(msg) -> list[dict]:
    timeline = []
    for hop, raw in enumerate(msg.get_all("Received", []), start=1):
        date_match = re.search(r";\s*(.+)$", raw, re.S)
        timestamp = None
        epoch = None
        if date_match:
            try:
                parsed = parsedate_to_datetime(date_match.group(1).strip())
                timestamp = parsed.isoformat()
                epoch = parsed.timestamp()
            except (TypeError, ValueError, OverflowError, OSError):
                timestamp = None
                epoch = None
        ips = extract_iocs(raw)["ips"]
        timeline.append({"hop": hop, "raw": str(raw), "timestamp": timestamp, "epoch": epoch, "ips": ips})
    ordered = sorted(timeline, key=lambda item: item["epoch"] if item["epoch"] is not None else float("inf"))
    for i in range(1, len(ordered)):
        prev, cur = ordered[i - 1], ordered[i]
        if prev["epoch"] is not None and cur["epoch"] is not None:
            cur["delta_seconds_from_previous"] = round(cur["epoch"] - prev["epoch"], 3)
        else:
            cur["delta_seconds_from_previous"] = None
    return ordered


def _auth_headers(headers: dict[str, str]) -> dict[str, str | bool | None]:
    auth_results = headers.get("Authentication-Results", "")
    return {
        "authentication_results": auth_results,
        "arc_authentication_results": headers.get("ARC-Authentication-Results", ""),
        "dkim_signature_present": bool(headers.get("DKIM-Signature")),
        "spf_result": _extract_result(auth_results, "spf"),
        "dkim_result": _extract_result(auth_results, "dkim"),
        "dmarc_result": _extract_result(auth_results, "dmarc"),
        "bimi_result": _extract_result(auth_results, "bimi"),
    }


def _extract_result(value: str, mechanism: str) -> str | None:
    match = re.search(rf"\b{re.escape(mechanism)}\s*=\s*([a-zA-Z]+)", value or "", re.I)
    return match.group(1).lower() if match else None


def _lookalike(sender_domain: str, link_domains: list[str]) -> list[dict]:
    result = []
    base = sender_domain.lower().strip(".")
    if not base:
        return result
    for domain in sorted({item.strip(".").lower() for item in link_domains if item}):
        if domain == base:
            continue
        same_core = base.replace("-", "").replace(".", "") == domain.replace("-", "").replace(".", "")
        digit_swap = re.sub(r"0", "o", domain) == re.sub(r"0", "o", base)
        one_label_prefix = domain.endswith("." + base) or base.endswith("." + domain)
        if same_core or digit_swap or one_label_prefix:
            result.append(
                {
                    "domain": domain,
                    "reason": "lookalike or parent/child domain relationship",
                }
            )
    return result


def analyze_email(data: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    headers = {str(k): _decode(str(v)) for k, v in msg.items()}
    subject = headers.get("Subject", "")
    from_value = headers.get("From", "")
    reply = headers.get("Reply-To", "")
    ret = headers.get("Return-Path", "")
    text_body, html_body, attachments = _extract_body(msg)
    link_info = _link_analysis(html_body)
    received = _received_timeline(msg)

    combined = "\n".join([subject, from_value, reply, ret, text_body, html_body])
    lower = combined.lower()
    iocs = extract_iocs(combined)
    urgency_terms = []
    score = 0
    for term, points in URGENCY.items():
        if term in lower:
            urgency_terms.append(term)
            score += points

    mismatches = []
    from_domain = _domain(from_value)
    reply_domain = _domain(reply)
    return_domain = _domain(ret)
    if from_domain and reply_domain and from_domain != reply_domain:
        mismatches.append("From and Reply-To domains differ")
    if return_domain and from_domain and return_domain != from_domain:
        mismatches.append("Return-Path domain differs from From")

    message_id = headers.get("Message-ID", "")
    message_id_domain = _domain(message_id)
    if message_id_domain and from_domain and message_id_domain != from_domain:
        mismatches.append("Message-ID domain differs from From")

    if mismatches:
        score += 15
    if link_info["hidden_text"]:
        score += 12
    credential_terms = [term for term in CREDENTIAL_TERMS if term in lower]
    if credential_terms:
        score += min(18, 4 * len(credential_terms))
    if attachments:
        score += min(20, 5 * len(attachments))
    dangerous_attachments = [a for a in attachments if a["dangerous_extension"]]
    if dangerous_attachments:
        score += 15
    external_form_domains = []
    for form in link_info["forms"]:
        try:
            domain = urlparse(form["action"]).hostname or ""
        except ValueError:
            domain = ""
        if domain:
            external_form_domains.append(domain.lower())
    password_forms = [form for form in link_info["forms"] if form["password_field"]]
    if link_info["forms"]:
        score += 15
    if password_forms:
        score += min(20, 10 * len(password_forms))
    if any(link["domain_mismatch"] for link in link_info["links"]):
        score += 18
    if any(link["javascript_scheme"] or link["data_scheme"] for link in link_info["links"]):
        score += 25
    if link_info["tracking_pixels"]:
        score += 3

    behavior_findings_list, techniques, behavior_score = behavior_findings(combined)
    score += min(20, behavior_score // 2)
    link_domains = [link["domain"] for link in link_info["links"]] + external_form_domains
    lookalikes = _lookalike(from_domain, link_domains)
    if lookalikes:
        score = min(100, score + 10)

    auth = _auth_headers(headers)
    auth["spf_alignment_note"] = "SPF result is taken from Authentication-Results; authoritative verification requires receiver-side telemetry."
    auth["dkim_alignment_note"] = "DKIM-Signature presence does not by itself prove signature validity."
    auth["dmarc_alignment_note"] = "DMARC result is taken from Authentication-Results; independent DNS/receiver validation is outside this parser."
    header_inventory = {
        "header_count": len(headers),
        "received_hops": len(received),
        "has_message_id": bool(message_id),
        "has_reply_to": bool(reply),
        "has_return_path": bool(ret),
        "has_list_unsubscribe": bool(headers.get("List-Unsubscribe")),
        "x_mailer": headers.get("X-Mailer", ""),
        "x_originating_ip": extract_iocs(headers.get("X-Originating-IP", "")).get("ips", []),
    }
    body_profile = {
        "text_characters": len(text_body),
        "html_characters": len(html_body),
        "link_count": len(link_info["links"]),
        "form_count": len(link_info["forms"]),
        "attachment_count": len(attachments),
        "html_ratio": round(len(html_body) / max(1, len(text_body) + len(html_body)), 4),
    }
    for mechanism, points in (("dmarc_result", 8), ("spf_result", 6), ("dkim_result", 6)):
        if auth[mechanism] == "fail":
            score = min(100, score + points)

    score = min(100, score)
    correlation = correlate_evidence(iocs, techniques, link_info["links"] + link_info["forms"] + attachments)
    verdict = "phishing-likely" if score >= 55 else "suspicious" if score >= 25 else "low-risk"
    return {
        "subject": subject,
        "from": from_value,
        "reply_to": reply,
        "return_path": ret,
        "message_id": message_id,
        "received": received,
        "auth": auth,
        "header_inventory": header_inventory,
        "body_profile": body_profile,
        "urgency_terms": urgency_terms,
        "mismatches": mismatches,
        "hidden_text": link_info["hidden_text"],
        "credential_terms": credential_terms,
        "links": link_info["links"],
        "forms": link_info["forms"],
        "tracking_pixels": link_info["tracking_pixels"],
        "lookalike_domains": lookalikes,
        "attachments": attachments,
        "iocs": iocs,
        "behavior_findings": behavior_findings_list,
        "mitre_techniques": techniques,
        "correlation": correlation,
        "attribution_guardrail": attribution_guardrail(
            [item["id"] for item in techniques], len(iocs.get("ips", [])) + len(iocs.get("domains", []))
        ),
        "risk_score": score,
        "verdict": verdict,
        "analysis_engine": {
            "name": "PhishGuard Email Engine",
            "version": "2.5",
            "format": "RFC 5322/MIME parser",
            "static_only": True,
        },
        "notes": [
            "SPF/DKIM/DMARC/BIMI values are reported from Authentication-Results headers when present; this parser does not forge or assume authentication success.",
            "Received headers are treated as evidence supplied by the message and are not proof of the true originating host without independent mail-server telemetry.",
            "A suspicious email can be malicious without matching every heuristic; analyst review and external intelligence remain important.",
        ],
    }
