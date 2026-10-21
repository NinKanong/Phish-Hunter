from __future__ import annotations

def detect(events):
    # Current normalized parser does not expose Ethernet ARP mappings, so do not invent detections.
    return {'candidates':[],'status':'arp-layer evidence not retained by current bounded normalized event schema'}
