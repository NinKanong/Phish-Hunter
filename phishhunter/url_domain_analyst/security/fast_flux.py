from __future__ import annotations
from typing import Any


def assess(history:list[dict[str,Any]]) -> dict[str,Any]:
    events=[x for x in history or [] if isinstance(x,dict)]
    ips=[]; ttls=[]
    for x in events:
        ips += [str(v) for v in (x.get('ips') or [])]
        try: ttls.append(float(x.get('ttl')))
        except (TypeError,ValueError): pass
    uniq=len(set(ips));
    score=min(100, uniq*8 + (20 if len(events)>=10 else 0) + (20 if ttls and min(ttls)<300 else 0))
    return {'score':score,'unique_ips':uniq,'observations':len(events),'ttl_min':min(ttls) if ttls else None,'assessment':'requires-history' if not events else ('elevated-churn' if score>=60 else 'no-strong-fast-flux-signal')}
