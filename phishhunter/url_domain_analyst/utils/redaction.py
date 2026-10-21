from __future__ import annotations
import re
SECRET=re.compile(r"(?i)(password|passwd|secret|api[_-]?key|authorization|cookie)\s*[:=]\s*([^,;\s]+)")

def redact(text:str, replacement:str="<REDACTED>")->str:
    return SECRET.sub(lambda m:f"{m.group(1)}={replacement}",str(text))
