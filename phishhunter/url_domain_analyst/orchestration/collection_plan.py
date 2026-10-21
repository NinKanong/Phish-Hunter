from __future__ import annotations
from typing import Any

DEEP_STAGES=[
    ("01","Intake & normalization"),("02","URL anatomy"),("03","Domain anatomy"),("04","WHOIS / RDAP lifecycle"),
    ("05","DNS full stack"),("06","Mail security"),("07","DNSSEC posture"),("08","Certificate Transparency"),
    ("09","Passive DNS / historical"),("10","Subdomain discovery"),("11","Attack-surface inventory"),("12","IP / ASN / netblock"),
    ("13","System locations"),("14","Hosting / cloud"),("15","CDN / WAF"),("16","TLS"),("17","HTTP metadata"),
    ("18","Redirect / landing chain"),("19","Services / banners"),("20","Technology / third-party"),("21","Content / JS surface"),
    ("22","Reputation fusion"),("23","Breach / exposure providers"),("24","Advanced OSINT pivots"),("25","Relationship graph"),
    ("26","Risk scoring / calibration"),("27","AI evidence review"),("28","Evidence / chain of custody"),
    ("29","Report / export package"),("30","Monitoring plan"),
]

def build(profile: str = "deep", provider_states: dict[str,Any]|None = None) -> list[dict[str,Any]]:
    profile=(profile or "deep").lower()
    chosen=DEEP_STAGES if profile=="forensic" else DEEP_STAGES[:18] if profile=="quick" else DEEP_STAGES[:27]
    states=provider_states or {}
    out=[]
    for num,name in chosen:
        state="ready"
        provider=None
        key=name.lower().replace(" ","_")
        if "attack-surface" in name.lower(): provider=states.get("DNSDumpster") or "DNS-over-HTTPS fallback"
        if "reputation" in name.lower(): provider=states.get("VirusTotal") or states.get("urlscan.io") or "provider-dependent"
        if "breach" in name.lower(): provider=states.get("Have I Been Pwned") or "authorized-provider-dependent"
        if provider and "dependent" in str(provider): state="provider-dependent"
        out.append({"id":num,"name":name,"state":state,"provider":provider,"profile":profile})
    return out
