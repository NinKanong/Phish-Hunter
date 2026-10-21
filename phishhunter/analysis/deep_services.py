from __future__ import annotations

import csv
import io
import ipaddress
import json
import math
import re
import socket
import ssl
import struct
import zipfile
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from html import unescape
from pathlib import Path
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from phishhunter.analyzers.file_analyzer import analyze_file
from phishhunter.sandbox.manager import SandboxManager
from phishhunter_common.hash import hash_bytes
from phishhunter_common.ioc import extract_iocs

SUSPICIOUS_TERMS = {
    "credential": 10, "password": 8, "login": 6, "verify": 6, "otp": 8,
    "wallet": 7, "seed phrase": 12, "private key": 12, "disable defender": 15,
    "powershell": 10, "cmd.exe": 8, "mshta": 12, "rundll32": 12, "regsvr32": 12,
    "scheduled task": 10, "schtasks": 10, "shadow copy": 12, "vssadmin": 12,
    "encrypt": 8, "decrypt": 6, "ransom": 12, "bitcoin": 7, "tor": 5,
}
RANSOM_TERMS = {
    "your files": 12, "encrypted": 15, "decrypt": 10, "ransom": 20, "bitcoin": 8,
    "monero": 8, "payment": 5, "tor": 6, "recovery key": 12, "contact us": 3,
}
BRAND_TERMS = {
    "microsoft", "office365", "office 365", "outlook", "google", "gmail", "apple",
    "icloud", "facebook", "instagram", "linkedin", "paypal", "docusign", "adobe",
    "dropbox", "onedrive", "github", "okta", "cloudflare", "bank", "visa", "mastercard",
}


def json_safe(value):
    """Convert arbitrary analyzer values into strict JSON-safe primitives."""
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return None
        return value
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value[:256].hex()
    if isinstance(value, (set, frozenset, tuple, list)):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    # Covers Jinja Undefined and other lazy values without leaking them into JSON columns.
    return str(value)


def normalize_result(result: dict) -> dict:
    return json_safe(result)


def _dns_query(name: str, qtype: int, server: str = "8.8.8.8", timeout: float = 2.5) -> list[dict]:
    """Small dependency-free DNS client for common defensive record types."""
    labels = name.rstrip(".").split(".")
    packet = bytearray(struct.pack("!HHHHHH", 0x4B34, 0x0100, 1, 0, 0, 0))
    for label in labels:
        raw = label.encode("idna")
        if len(raw) > 63:
            return []
        packet.append(len(raw)); packet.extend(raw)
    packet.append(0); packet.extend(struct.pack("!HH", qtype, 1))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(8192)
    except OSError:
        return []
    finally:
        try: sock.close()
        except Exception: pass
    if len(data) < 12:
        return []
    _, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    if flags & 0x000F or an == 0:
        return []
    offset = 12
    def skip_name(pos: int) -> int:
        seen = 0
        while pos < len(data) and seen < 128:
            length = data[pos]
            if length == 0:
                return pos + 1
            if length & 0xC0 == 0xC0:
                return pos + 2
            pos += length + 1; seen += 1
        return len(data)
    for _ in range(qd):
        offset = skip_name(offset) + 4
    out = []
    total = an + ns + ar
    type_names = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}
    for _ in range(total):
        if offset + 10 > len(data): break
        offset = skip_name(offset)
        if offset + 10 > len(data): break
        typ, cls, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset+10]); offset += 10
        rstart = offset; rend = min(len(data), offset + rdlen)
        value = None
        if typ in (1, 28) and rdlen in (4, 16):
            try: value = str(ipaddress.ip_address(data[rstart:rend]))
            except ValueError: value = None
        elif typ in (2, 5):
            p = rstart; labels_out=[]
            for _x in range(32):
                if p >= rend: break
                ln = data[p]
                if ln == 0: p += 1; break
                if ln & 0xC0 == 0xC0:
                    ptr = ((ln & 0x3F) << 8) | data[p+1]
                    # Pointer decoder with a bounded recursion.
                    q = ptr; seen=set()
                    while q < len(data) and q not in seen and len(labels_out) < 32:
                        seen.add(q); l=data[q]
                        if l == 0: break
                        if l & 0xC0 == 0xC0:
                            q=((l&0x3F)<<8)|data[q+1]; continue
                        labels_out.append(data[q+1:q+1+l].decode("idna", "replace")); q += l+1
                    p += 2; break
                labels_out.append(data[p+1:p+1+ln].decode("idna", "replace")); p += ln+1
            value = ".".join(labels_out) + "."
        elif typ == 15 and rdlen >= 3:
            pref = struct.unpack("!H", data[rstart:rstart+2])[0]
            # MX exchange follows DNS name encoding.
            p = rstart + 2; labels_out=[]
            for _x in range(32):
                if p >= rend: break
                ln=data[p]
                if ln == 0: break
                if ln & 0xC0 == 0xC0:
                    q=((ln&0x3F)<<8)|data[p+1]; seen=set()
                    while q < len(data) and q not in seen and len(labels_out)<32:
                        seen.add(q); l=data[q]
                        if l == 0: break
                        if l & 0xC0 == 0xC0: q=((l&0x3F)<<8)|data[q+1]; continue
                        labels_out.append(data[q+1:q+1+l].decode("idna", "replace")); q += l+1
                    p += 2; break
                labels_out.append(data[p+1:p+1+ln].decode("idna", "replace")); p += ln+1
            value = {"preference": pref, "exchange": ".".join(labels_out)+"."}
        elif typ == 16:
            parts=[]; p=rstart
            while p < rend:
                ln=data[p]; p += 1; parts.append(data[p:p+ln].decode("utf-8", "replace")); p += ln
            value = "".join(parts)
        if value is not None:
            out.append({"type": type_names.get(typ, str(typ)), "ttl": ttl, "value": value})
        offset = rend
    return out


def deep_domain_analysis(domain: str) -> dict:
    host = domain.strip().lower().rstrip(".")
    if not host:
        raise ValueError("Domain is required")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid IDN domain: {exc}") from exc
    labels = ascii_host.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        raise ValueError("Input does not look like a valid DNS hostname")
    addresses = []
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(ascii_host, None)})
    except OSError:
        pass
    records = {}
    for qname, qtype in (("A",1),("AAAA",28),("CNAME",5),("MX",15),("NS",2),("TXT",16)):
        records[qname] = _dns_query(ascii_host, qtype)
    try:
        reverse = socket.gethostbyaddr(addresses[0])[0] if addresses else ""
    except (OSError, socket.herror):
        reverse = ""
    evidence=[]; score=0
    if any(label.startswith("xn--") for label in labels): score += 12; evidence.append({"signal":"punycode","severity":"medium","detail":"IDNA/punycode label present","points":12})
    if len(labels) >= 5: score += 7; evidence.append({"signal":"deep-subdomain","severity":"low","detail":"Five or more DNS labels","points":7})
    if any(len(label) > 30 for label in labels): score += 4; evidence.append({"signal":"long-label","severity":"low","detail":"Unusually long DNS label","points":4})
    txt = " ".join(str(x.get("value","")) for x in records.get("TXT", []))
    if "v=spf1" not in txt.lower(): evidence.append({"signal":"no-visible-spf","severity":"info","detail":"No SPF TXT record observed by the configured resolver","points":0})
    return normalize_result({
        "analysis_engine":{"name":"K4 Domain Deep Engine","version":"10.1"},
        "verdict":"suspicious" if score >= 20 else "review" if score else "unknown",
        "risk_score":min(100,score), "domain":ascii_host, "unicode_domain":host,
        "labels":labels, "label_count":len(labels), "addresses":addresses, "reverse_dns":reverse,
        "dns_records":records, "iocs":{"domains":[ascii_host],"ips":addresses}, "evidence":evidence,
        "collection":{"resolver":"8.8.8.8/UDP","network_collection":True},
    })


def deep_ip_analysis(value: str) -> dict:
    raw=value.strip()
    try: addr=ipaddress.ip_address(raw)
    except ValueError as exc: raise ValueError(f"Invalid IP address: {exc}") from exc
    try: reverse=socket.gethostbyaddr(raw)[0]
    except (OSError, socket.herror): reverse=""
    evidence=[]; score=0
    if addr.is_private: evidence.append({"signal":"private","severity":"info","detail":"RFC1918/private address","points":0})
    if addr.is_loopback: evidence.append({"signal":"loopback","severity":"info","detail":"Loopback address","points":0})
    if addr.is_reserved: evidence.append({"signal":"reserved","severity":"info","detail":"Reserved address space","points":0})
    if addr.is_multicast: evidence.append({"signal":"multicast","severity":"info","detail":"Multicast address","points":0})
    return normalize_result({
        "analysis_engine":{"name":"K4 IP Deep Engine","version":"10.1"}, "verdict":"unknown", "risk_score":score,
        "ip":str(addr), "version":addr.version,
        "classification":{"global":addr.is_global,"private":addr.is_private,"loopback":addr.is_loopback,"link_local":addr.is_link_local,"multicast":addr.is_multicast,"reserved":addr.is_reserved,"unspecified":addr.is_unspecified},
        "reverse_dns":reverse, "iocs":{"ips":[str(addr)],"domains":[reverse] if reverse else []}, "evidence":evidence,
        "notes":["ASN, geolocation and reputation are provider-backed capabilities and are not fabricated locally."],
    })


def deep_ioc_analysis(text: str) -> dict:
    value=text.strip()
    if not value: raise ValueError("IOC text is required")
    iocs=extract_iocs(value)
    lower=value.lower(); evidence=[]; score=0
    counts={k:len(v) for k,v in iocs.items()}
    if counts["hashes"]: evidence.append({"signal":"hashes","severity":"info","detail":f"{counts['hashes']} cryptographic hash candidate(s)","points":0})
    if counts["urls"]: score += min(25,counts["urls"]*5); evidence.append({"signal":"urls","severity":"medium","detail":f"{counts['urls']} URL(s) observed","points":min(25,counts['urls']*5)})
    if any(term in lower for term in ("password","credential","otp","login")):
        score += 15; evidence.append({"signal":"credential-context","severity":"high","detail":"Credential-related language accompanies the indicators","points":15})
    if any(u.lower().startswith(("http://","https://")) for u in iocs["urls"]):
        for u in iocs["urls"]:
            try:
                p=urlparse(u)
                if p.username or p.hostname and any(ch in p.hostname for ch in "[]"):
                    score += 10; evidence.append({"signal":"url-userinfo-or-unusual-host","severity":"high","detail":u[:240],"points":10})
            except ValueError: pass
    normalized={k:sorted(set(v)) for k,v in iocs.items()}
    return normalize_result({
        "analysis_engine":{"name":"K4 IOC Correlation Engine","version":"10.1"},
        "verdict":"suspicious" if score>=25 else "review" if score else "unknown", "risk_score":min(100,score),
        "input":value[:10000], "iocs":normalized, "counts":counts, "evidence":evidence,
        "relationships":{"domains_to_urls":[{"domain":urlparse(u).hostname,"url":u} for u in normalized["urls"] if urlparse(u).hostname],"indicator_count":sum(counts.values())},
        "confidence":"heuristic", "attribution":"not asserted from IOC extraction alone",
    })


def _text_signals(text: str, terms: dict[str,int]) -> tuple[int,list[dict]]:
    lower=text.lower(); score=0; findings=[]
    for term, points in terms.items():
        if term in lower:
            score += points; findings.append({"signal":term,"severity":"high" if points>=12 else "medium","detail":f"Observed static marker: {term}","points":points})
    return score, findings


def deep_phishing_kit_analysis(filename: str, data: bytes) -> dict:
    files=[]; combined_parts=[]; archive=False
    if data[:4] == b"PK\x03\x04":
        archive=True
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos=z.infolist()[:1000]
                for info in infos:
                    if info.is_dir(): continue
                    files.append({"name":info.filename,"size":info.file_size,"compressed":info.compress_size})
                    if info.file_size <= 2_000_000 and (info.filename.lower().endswith(('.html','.htm','.js','.css','.json','.txt'))):
                        combined_parts.append(z.read(info)[:2_000_000].decode("utf-8","replace"))
        except zipfile.BadZipFile:
            raise ValueError("ZIP container is malformed")
    else:
        combined_parts=[data[:5_000_000].decode("utf-8","replace")]
        files=[{"name":filename,"size":len(data),"compressed":len(data)}]
    text="\n".join(combined_parts); iocs=extract_iocs(text); score,findings=_text_signals(text,SUSPICIOUS_TERMS)
    soup=BeautifulSoup(text,"html.parser")
    forms=[]
    for form in soup.find_all("form"):
        action=form.get("action") or ""; fields=[str(x.get("name") or x.get("type") or "") for x in form.find_all("input")]
        forms.append({"action":action,"method":str(form.get("method") or "get").lower(),"fields":fields[:100],"password":any(x.lower() in {"password","passwd","pwd","pass"} for x in fields) or any(str(x.get("type") or "").lower() == "password" for x in form.find_all("input"))})
    external_actions=[x for x in forms if x["action"] and (urlparse(x["action"]).hostname or "")]
    if any(x["password"] for x in forms): score+=20; findings.append({"signal":"credential-form","severity":"critical","detail":"Password input found in an analyzed page","points":20})
    if external_actions: score+=10; findings.append({"signal":"external-form-action","severity":"high","detail":f"{len(external_actions)} form(s) specify an absolute external action","points":10})
    obfuscation=len(re.findall(r"(?:eval\s*\(|atob\s*\(|fromCharCode|unescape\s*\(|String\.fromCharCode)",text,re.I))
    if obfuscation: score+=min(25,obfuscation*6); findings.append({"signal":"javascript-obfuscation","severity":"high","detail":f"{obfuscation} common obfuscation marker(s)","points":min(25,obfuscation*6)})
    brands=sorted({brand for brand in BRAND_TERMS if brand in text.lower()})
    if brands: findings.append({"signal":"brand-reference","severity":"info","detail":", ".join(brands),"points":0})
    return normalize_result({
        "analysis_engine":{"name":"K4 Phishing Kit Deep Engine","version":"10.1"},
        "verdict":"malicious" if score>=50 else "suspicious" if score>=20 else "review" if findings else "unknown",
        "risk_score":min(100,score), "filename":filename, "archive":archive,"files":files[:1000],
        "forms":forms[:200],"brand_references":brands,"obfuscation_markers":obfuscation,
        "iocs":iocs,"evidence":findings,"static_only":True,
        "notes":["HTML/JavaScript is inspected as text; scripts are never executed by the web process."],
    })


def deep_ransomware_analysis(filename: str, data: bytes) -> dict:
    base=analyze_file(filename,data); raw=data[:8_000_000].decode("utf-8","replace")
    score,findings=_text_signals(raw,RANSOM_TERMS)
    lower=filename.lower()+" "+raw.lower()
    if any(term in lower for term in (".locked",".encrypted","ransom")):
        score+=15; findings.append({"signal":"ransom-artifact-name","severity":"high","detail":"Filename/content contains a ransomware-associated marker","points":15})
    if base.get("content_looks_executable"): score+=5; findings.append({"signal":"executable","severity":"medium","detail":"Artifact appears executable","points":5})
    result=dict(base)
    result.update({"analysis_engine":{"name":"K4 Ransomware Triage Engine","version":"10.1"},"risk_score":min(100,max(int(base.get("risk_score",0)),score)),"verdict":"suspicious" if score>=20 else base.get("verdict","unknown"),"ransomware_findings":findings,"ransomware_context":{"static_only":True,"dynamic_execution":"external sandbox required"}})
    return normalize_result(result)


def deep_feed_analysis(source: str, text: str) -> dict:
    raw=text.strip(); items=[]; fmt="text"
    if not raw: raise ValueError("Feed content is required")
    try:
        obj=json.loads(raw); fmt="json"
        candidates=obj.get("objects",[]) if isinstance(obj,dict) else obj
        if isinstance(candidates,list):
            for item in candidates:
                if not isinstance(item,dict): continue
                for key in ("value","indicator","url","domain","ip","hash"):
                    if item.get(key): items.append(str(item[key]))
    except json.JSONDecodeError:
        if "," in raw.splitlines()[0]:
            fmt="csv"; reader=csv.DictReader(io.StringIO(raw))
            for row in reader:
                items.extend(str(v) for k,v in row.items() if k and k.lower() in {"indicator","value","url","domain","ip","hash"} and v)
        else:
            items=[line.strip() for line in raw.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    extracted=extract_iocs("\n".join(items)); unique=sorted(set(items));
    return normalize_result({"analysis_engine":{"name":"K4 Feed Ingestion Engine","version":"10.1"},"source":source or "uploaded-feed","format":fmt,"raw_items":len(items),"unique_items":len(unique),"duplicates":len(items)-len(unique),"iocs":extracted,"sample":unique[:200],"status":"parsed"})


def sandbox_manifest(sha256: str) -> dict:
    result=SandboxManager().submit(sha256.strip())
    return normalize_result({"analysis_engine":{"name":"K4 Sandbox Orchestrator","version":"10.1"},"status":result.status,"backend":result.backend,"evidence":result.evidence,"execution": {"local":False,"external_provider_required":result.status in {"queued","misconfigured"}}})
