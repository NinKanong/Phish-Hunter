from __future__ import annotations
import hashlib
from typing import Any

def fingerprint_tls(observations: list[dict[str,Any]]) -> dict[str,Any]:
    # Passive metadata fingerprinting. Full JA3/JA4 requires raw ClientHello extension/cipher vectors.
    fingerprints=[]
    for obs in observations:
        sni=str(obs.get('sni') or '')
        material=f"{obs.get('dst_port')}|{sni.lower()}|tls"
        fingerprints.append({'family':'metadata','fingerprint':hashlib.sha256(material.encode()).hexdigest()[:32],'sni':sni,'dst_port':obs.get('dst_port'),'timestamp':obs.get('timestamp'),'note':'Metadata fingerprint; not a standards-complete JA3/JA4 value.'})
    return {'ja3':[],'ja3s':[],'ja4':[],'metadata_fingerprints':fingerprints[:1000],'status':'partial_passive'}
