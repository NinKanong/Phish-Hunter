from __future__ import annotations
import base64, binascii, html, re, urllib.parse

_PERCENT = re.compile(r'%[0-9a-fA-F]{2}')
_HEX = re.compile(r'^[0-9A-Fa-f]{8,}$')
_BASE64 = re.compile(r'^[A-Za-z0-9+/=_-]{12,}$')


def decode_layers(value: str, max_layers: int = 4) -> list[dict[str, str]]:
    layers=[{'method':'raw','value':value}]; cur=value
    for _ in range(max_layers):
        changed=False
        try:
            nxt=urllib.parse.unquote(cur)
            if nxt != cur:
                layers.append({'method':'percent-decode','value':nxt}); cur=nxt; changed=True
        except Exception: pass
        ent=html.unescape(cur)
        if ent != cur:
            layers.append({'method':'html-entity-decode','value':ent}); cur=ent; changed=True
        if not changed: break
    return layers


def looks_base64(value: str) -> bool:
    v=value.strip()
    if not _BASE64.match(v): return False
    try:
        base64.b64decode(v + '='*((4-len(v)%4)%4), validate=False)
        return True
    except (binascii.Error, ValueError):
        return False


def looks_hex(value: str) -> bool:
    return bool(_HEX.match(value.strip())) and len(value.strip()) % 2 == 0
