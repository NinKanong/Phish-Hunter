from __future__ import annotations

import re
import socket
import ssl
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from phishhunter.security.url_guard import resolve_and_validate, url_features, validate_url
from phishhunter.utils.analysis import behavior_findings
from phishhunter.mitre import attribution_guardrail
from phishhunter.utils.http import fetch_url
from phishhunter_common.ioc import extract_iocs
from phishhunter.analysis.correlation import correlate_evidence


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def _tls_metadata(parsed, connect_ip: str | None = None) -> dict | None:
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    try:
        host = parsed.hostname.encode("idna").decode("ascii")
        address = connect_ip or resolve_and_validate(host, parsed.port or 443)[0]
        context = ssl.create_default_context()
        with socket.create_connection((address, parsed.port or 443), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                return {
                    "version": sock.version(),
                    "cipher": sock.cipher(),
                    "peer_ip": address,
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("not_after") or cert.get("notAfter"),
                    "san": cert.get("subjectAltName", []),
                }
    except Exception as exc:
        return {"error": str(exc)}


def _forms_and_links(base_url: str, html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        target = urljoin(base_url, action)
        fields = []
        for field in form.find_all(["input", "select", "textarea", "button"]):
            fields.append(
                {
                    "name": field.get("name"),
                    "type": field.get("type", field.name),
                    "autocomplete": field.get("autocomplete"),
                }
            )
        forms.append(
            {
                "action": target,
                "method": (form.get("method") or "get").lower(),
                "fields": fields[:100],
                "cross_origin": (urlparse(target).hostname or "").lower() != (urlparse(base_url).hostname or "").lower(),
            }
        )

    links = []
    for anchor in soup.find_all("a", href=True):
        href = urljoin(base_url, anchor.get("href", ""))
        try:
            parsed = urlparse(href)
            domain = parsed.hostname or ""
        except ValueError:
            domain = ""
        links.append(
            {
                "url": href,
                "domain": domain.lower(),
                "text": anchor.get_text(" ", strip=True)[:180],
                "external": bool(domain and domain.lower() != (urlparse(base_url).hostname or "").lower()),
            }
        )
    scripts = [script.get_text(" ", strip=False)[:20000] for script in soup.find_all("script")]
    meta_refresh = [
        meta.get("content", "") for meta in soup.find_all("meta") if str(meta.get("http-equiv", "")).lower() == "refresh"
    ]
    return {"forms": forms[:200], "links": links[:500], "scripts": scripts[:100], "meta_refresh": meta_refresh[:50], "soup": soup}


def _security_header_report(headers: dict) -> dict:
    lower = {key.lower(): value for key, value in headers.items()}
    return {label: bool(lower.get(header)) for header, label in SECURITY_HEADERS.items()}


def _host_risk_features(url: str) -> list[dict]:
    features = url_features(url)
    evidence = []
    for field, message, severity, points in (
        ("hostname_is_ip", "URL uses a numeric IP address instead of a hostname", "medium", 10),
        ("punycode", "Hostname contains IDN/punycode label", "medium", 8),
        ("at_symbol", "URL contains @ userinfo delimiter", "high", 15),
        ("encoded_path", "Path contains percent-encoded characters", "low", 3),
        ("suspicious_tld", "Hostname uses a commonly abused disposable TLD", "medium", 6),
        ("dash_in_hostname", "Hostname contains hyphenated labels", "low", 2),
    ):
        if features.get(field):
            evidence.append({"signal": field, "severity": severity, "detail": message, "points": points})
    if features.get("subdomain_count", 0) >= 4:
        evidence.append({"signal": "deep-subdomain", "severity": "medium", "detail": "Four or more subdomain labels", "points": 7})
    return evidence


async def analyze_url(url: str) -> dict:
    url = validate_url(url)
    parsed = urlparse(url)
    dns = resolve_and_validate(parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80))
    http = await fetch_url(url)
    html = http.pop("content")
    page = _forms_and_links(http["final_url"], html)
    soup = page.pop("soup")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    text = soup.get_text(" ", strip=True)[:200_000]
    findings, techniques, behavior_score = behavior_findings(html)
    iocs = extract_iocs(html + "\n" + http.get("final_url", url) + "\n" + "\n".join(item["url"] for item in page["links"]))

    evidence = _host_risk_features(url)
    evidence.extend(_host_risk_features(http["final_url"]))
    password_forms = [
        form for form in page["forms"] if any(str(field.get("type")).lower() == "password" for field in form["fields"])
    ]
    cross_origin_forms = [form for form in page["forms"] if form["cross_origin"]]
    base_host = (urlparse(http["final_url"]).hostname or "").lower()
    external_links = [link for link in page["links"] if link.get("external")]
    third_party_script_count = 0
    for script in soup.find_all("script", src=True):
        src = urljoin(http["final_url"], script.get("src") or "")
        if (urlparse(src).hostname or "").lower() not in {base_host, ""}:
            third_party_script_count += 1
    page_profile = {
        "text_characters": len(text),
        "link_count": len(page["links"]),
        "external_link_count": len(external_links),
        "form_count": len(page["forms"]),
        "password_form_count": len(password_forms),
        "script_count": len(page["scripts"]),
        "third_party_script_count": third_party_script_count,
        "meta_refresh_count": len(page["meta_refresh"]),
    }
    if password_forms:
        evidence.append({"signal": "password-form", "severity": "high", "detail": f"{len(password_forms)} password form(s)", "points": 18})
    if cross_origin_forms:
        evidence.append({"signal": "cross-origin-form", "severity": "high", "detail": f"{len(cross_origin_forms)} form action(s) leave the page origin", "points": 18})
    if http.get("redirect_count", 0) >= 3:
        evidence.append({"signal": "redirect-chain", "severity": "medium", "detail": http["redirect_count"], "points": 10})
    if re.search(r"(?i)document\.location|window\.location|eval\s*\(|atob\s*\(|fromcharcode", "\n".join(page["scripts"])):
        evidence.append({"signal": "suspicious-javascript", "severity": "high", "detail": "Obfuscation or navigation code markers detected", "points": 16})
    if page["meta_refresh"]:
        evidence.append({"signal": "meta-refresh", "severity": "medium", "detail": len(page["meta_refresh"]), "points": 6})

    score = behavior_score + sum(item.get("points", 0) for item in evidence)
    if "login" in title.lower() or "verify" in text.lower():
        score += 8
    score = min(100, score)
    verdict = "phishing-likely" if score >= 55 else "suspicious" if score >= 25 else "low-risk"
    correlation = correlate_evidence(iocs, techniques, page["links"] + page["forms"])
    return {
        "url": url,
        "features": url_features(url),
        "dns": dns,
        "tls": _tls_metadata(parsed, http.get("resolved_ip")),
        "http": http,
        "title": title,
        "forms": page["forms"],
        "links": page["links"],
        "security_headers": _security_header_report(http.get("headers", {})),
        "page_profile": page_profile,
        "iocs": iocs,
        "findings": findings,
        "mitre_techniques": techniques,
        "correlation": correlation,
        "attribution_guardrail": attribution_guardrail([item["id"] for item in techniques], len(iocs.get("ips", [])) + len(iocs.get("domains", []))),
        "evidence": evidence,
        "risk_score": score,
        "verdict": verdict,
        "analysis_engine": {"name": "PhishGuard URL Engine", "version": "2.5", "ssrf_guard": True, "redirect_revalidation": True},
        "notes": [
            "Every requested URL and every HTTP redirect is DNS/IP revalidated to reduce SSRF and DNS-rebinding risk.",
            "The collector does not run JavaScript or browser automation on the application host.",
            "Brand/actor attribution requires corroborating evidence and external intelligence; heuristics alone are not attribution.",
        ],
    }
