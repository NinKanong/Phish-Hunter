from __future__ import annotations
WATCH_TYPES=['domain','subdomain','url','certificate','asn','ip','registrar','keyword','brand','regex','favicon','kit-signature']
TRIGGERS=['new-subdomain','dns-change','certificate-issued','certificate-change','rdap-change','screenshot-change','content-drift','reputation-drop','blocklist-hit','new-registration','takeover-signal']
ACTIONS=['alert','webhook','ticket','email','slack','teams','soar','rescan','pivot','evidence-capture']

def manifest()->dict: return {'watch_types':WATCH_TYPES,'triggers':TRIGGERS,'actions':ACTIONS,'cadence':['streaming','hourly','daily','weekly','on-demand','adaptive']}
