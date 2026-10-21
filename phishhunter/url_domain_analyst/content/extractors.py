from __future__ import annotations
import re

def extract_iocs(text: str|None) -> dict:
    s=str(text or "")
    urls=sorted(set(re.findall(r"https?://[^\s\"<>]+",s)))
    emails=sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",s)))
    ipv4=sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",s)))
    hashes=sorted(set(re.findall(r"\b[a-fA-F0-9]{64}\b",s)))
    return {"urls":urls[:500],"emails":emails[:500],"ipv4":ipv4[:500],"sha256":hashes[:500]}
