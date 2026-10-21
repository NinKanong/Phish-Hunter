from __future__ import annotations

RELATION_TYPES = ["observed-in","resolves-to","reverse-resolves-to","hosted-by","served-by","shares-certificate-with","uses-technology","redirects-to","registered-with","related-to","mentioned-by","clusters-with","generated-from","supports"]

def relationship_contract() -> dict:
    return {"node_types": ["target","domain","url","ip","certificate","nameserver","mailserver","technology","ioc","case","campaign","actor","evidence"], "edge_types": RELATION_TYPES}
