from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![\w:])")
HASH = re.compile(r"\b[a-fA-F0-9]{32,128}\b")
DOMAIN = re.compile(
    r"(?<![@\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?![\w-])"
)
URL = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+")
DEFFANG_URL = re.compile(r"(?i)\b(?:hxxps?|https?)\s*(?:\[:\]|\[\.\]|:\s*)/{2}[^\s\"'<>]+")
EMAIL = re.compile(r"\b[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+\b")


def _defang(value: str) -> str:
    normalized = value.strip()
    normalized = re.sub(r"(?i)^hxxps?\s*://", lambda m: "https://" if m.group(0).lower().startswith("hxxps") else "http://", normalized)
    normalized = re.sub(r"(?i)^hxxps?\s*\[:\]\s*//", lambda m: "https://" if m.group(0).lower().startswith("hxxps") else "http://", normalized)
    normalized = re.sub(r"(?i)^hxxps?\s*\[\.\]", lambda m: "https://" if m.group(0).lower().startswith("hxxps") else "http://", normalized)
    normalized = normalized.replace("[.]", ".")
    return normalized


def _canonical_domain(value: str) -> str | None:
    try:
        host = urlparse(value).hostname
    except ValueError:
        host = None
    if not host:
        return None
    try:
        return host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return host.lower().rstrip(".")


def extract_iocs(text: str) -> dict[str, list[str]]:
    ips: set[str] = set()
    for value in [*IPV4.findall(text), *IPV6.findall(text)]:
        try:
            ips.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue

    raw_urls = [*URL.findall(text), *DEFFANG_URL.findall(text)]
    urls = {_defang(value).rstrip(".,);]") for value in raw_urls}
    domains = set(DOMAIN.findall(text))
    hashes = set(HASH.findall(text))
    emails = set(EMAIL.findall(text))
    for value in urls:
        domain = _canonical_domain(value)
        if domain:
            domains.add(domain)

    return {
        "ips": sorted(ips),
        "ipv4": sorted([ip for ip in ips if "." in ip]),
        "ipv6": sorted([ip for ip in ips if ":" in ip]),
        "urls": sorted(urls),
        "domains": sorted(d.lower().rstrip(".") for d in domains),
        "hashes": sorted(hashes),
        "emails": sorted(emails),
    }
