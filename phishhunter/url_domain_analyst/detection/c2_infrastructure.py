from __future__ import annotations
import math, re
from collections import Counter
from urllib.parse import urlparse
from typing import Any

SUSPICIOUS_PATHS = re.compile(r"/(?:gate|c2|cnc|command|callback|beacon|checkin|implant|payload|bot|loader|dropper|panel|control|task|jobs|api/(?:v1/)?(?:beacon|checkin|command))(?=/|\?|$)", re.I)
C2_WORDS = re.compile(r"\b(?:c2|c&c|command(?:-| )and(?:-| )control|botnet|beacon|beaconing|callback|check[- ]?in|malware|implant|loader|dropper|rat|stealer)\b", re.I)

PROVIDER_KEYS = ("VirusTotal", "URLhaus", "AlienVault OTX", "AbuseIPDB", "OpenPhish", "PhishTank", "urlscan.io")

def _walk(obj: Any):
    if isinstance(obj, dict):
        for k,v in obj.items():
            yield str(k), v
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)

def _provider_hits(result: dict[str, Any]) -> list[dict[str, Any]]:
    hits=[]
    providers=result.get("provider_results") if isinstance(result.get("provider_results"),dict) else {}
    rep=result.get("reputation") if isinstance(result.get("reputation"),dict) else {}
    for name in PROVIDER_KEYS:
        payload=providers.get(name)
        if payload in (None, {}, [], ""): continue
        text=str(payload)
        if C2_WORDS.search(text):
            hits.append({"provider":name,"indicator":"provider payload contains C2/malware terminology","confidence":"provider-returned","raw_summary":text[:600]})
    for sig in rep.get("signals") or []:
        if isinstance(sig,dict) and C2_WORDS.search(str(sig)):
            hits.append({"provider":"reputation-fusion","indicator":str(sig)[:300],"confidence":"derived-from-provider"})
    return hits

def _dns_indicators(result: dict[str, Any]) -> list[dict[str, Any]]:
    out=[]
    dns=result.get("dns") if isinstance(result.get("dns"),dict) else {}
    records=dns.get("records") if isinstance(dns.get("records"),dict) else {}
    labels=[]
    for typ in ("A","AAAA","CNAME","TXT","NS"):
        for row in records.get(typ) or []:
            if isinstance(row,dict):
                for key in ("name","host","value","target","exchange"):
                    if row.get(key): labels.append(str(row[key]))
    for label in labels[:300]:
        token=str(label).split('.')[0]
        if len(token)>=18 and len(set(token.lower()))/max(1,len(token))>.55:
            out.append({"indicator":"high-entropy DNS label","value":label[:255],"confidence":"heuristic"})
        if C2_WORDS.search(label):
            out.append({"indicator":"C2-like DNS naming","value":label[:255],"confidence":"heuristic"})
    return out[:50]

def _web_indicators(result: dict[str, Any]) -> list[dict[str, Any]]:
    out=[]
    http=result.get("http") if isinstance(result.get("http"),dict) else {}
    urls=[]
    for key in ("url","final_url","redirect_chain"):
        value=http.get(key)
        if isinstance(value,str): urls.append(value)
        elif isinstance(value,list): urls.extend(str(x.get("url") or x) if isinstance(x,dict) else str(x) for x in value)
    for link in http.get("links") or []:
        if isinstance(link,dict) and link.get("url"): urls.append(str(link["url"]))
        elif isinstance(link,str): urls.append(link)
    for value in urls[:500]:
        if SUSPICIOUS_PATHS.search(value):
            out.append({"indicator":"C2-like HTTP path","value":value[:500],"confidence":"heuristic"})
        elif C2_WORDS.search(value):
            out.append({"indicator":"C2 terminology in public URL","value":value[:500],"confidence":"heuristic"})
    return out[:50]

def analyze(result: dict[str, Any]) -> dict[str, Any]:
    provider_hits=_provider_hits(result)
    indicators=_dns_indicators(result)+_web_indicators(result)
    fast_flux=result.get("fast_flux") if isinstance(result.get("fast_flux"),dict) else {}
    if fast_flux.get("suspicious") or fast_flux.get("score",0)>70:
        indicators.append({"indicator":"fast-flux-like DNS behavior","value":fast_flux,"confidence":"derived"})
    score=0
    if provider_hits: score += min(70, 45*len(provider_hits))
    score += min(20, 5*len(indicators))
    if fast_flux.get("suspicious"): score += 15
    score=min(100,score)
    if provider_hits:
        verdict="provider-observed-suspicious"
        confidence="high"
    elif score>=55:
        verdict="suspected-c2-infrastructure"
        confidence="medium"
    elif score>=25:
        verdict="c2-like-indicators"
        confidence="low"
    else:
        verdict="no-c2-observation"
        confidence="none"
    return {
        "status":"complete",
        "scope":"defensive C2 / malware-infrastructure triage; no beaconing, exploitation, or command execution",
        "verdict":verdict,"score":score,"confidence":confidence,
        "provider_hits":provider_hits[:30],"indicators":indicators[:80],
        "mitre_context":["T1071.001 Web Protocols"] if (provider_hits or indicators) else [],
        "analyst_note":"A heuristic C2 signal is not proof of malicious control. Provider-returned intelligence is kept separate from heuristics."
    }
