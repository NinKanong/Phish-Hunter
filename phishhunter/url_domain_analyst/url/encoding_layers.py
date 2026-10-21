from __future__ import annotations
import base64, binascii, html, re, urllib.parse
from typing import Any

HEX_RE = re.compile(r'^(?:[0-9a-fA-F]{2})+$')
B64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')


def bounded_url_decode(value: str, rounds: int = 3) -> list[dict[str, Any]]:
    """Return a bounded decode chain; never executes decoded content."""
    current = str(value or '')
    out=[{'round':0,'value':current,'changed':False,'technique':'raw'}]
    for i in range(1, max(1, min(rounds, 5))+1):
        decoded=urllib.parse.unquote(current)
        changed=decoded != current
        if not changed: break
        out.append({'round':i,'value':decoded[:10000],'changed':True,'technique':'percent-decode'})
        current=decoded
    return out


def detect_encoding_layers(value: str) -> list[dict[str, Any]]:
    s=str(value or '').strip()
    findings=[]
    if '%' in s:
        findings.append({'technique':'percent-encoding','confidence':98,'evidence':'%HH sequences present'})
        if re.search(r'%25[0-9A-Fa-f]{2}',s): findings.append({'technique':'double-encoding','confidence':99,'evidence':'%25HH sequence present'})
    if B64_RE.fullmatch(s) and len(s)>=16 and len(s)%4==0:
        try:
            raw=base64.b64decode(s,validate=True)
            if raw and sum(32 <= b < 127 for b in raw)/len(raw)>.55:
                findings.append({'technique':'base64','confidence':84,'evidence':'base64 decodes to mostly printable bytes'})
        except (ValueError,binascii.Error): pass
    if HEX_RE.fullmatch(s) and len(s)>=16:
        try:
            raw=bytes.fromhex(s)
            if raw and sum(32 <= b < 127 for b in raw)/len(raw)>.55:
                findings.append({'technique':'hex','confidence':78,'evidence':'hex decodes to mostly printable bytes'})
        except ValueError: pass
    if '&' in s and re.search(r'&(?:#x?[0-9a-f]+|[A-Za-z]+);', s, re.I):
        findings.append({'technique':'html-entity','confidence':96,'evidence':'HTML entity markers present'})
    if s.lower().startswith(('data:','javascript:','vbscript:')):
        findings.append({'technique':'active-uri-scheme','confidence':99,'evidence':'Active/data URI scheme'})
    return findings


def safe_entity_decode(value: str) -> str:
    return html.unescape(str(value or ''))[:20000]
