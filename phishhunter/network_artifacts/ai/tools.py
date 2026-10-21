from __future__ import annotations
from typing import Any

def summarize_events(events): return {'count':len(events),'first':events[0] if events else None,'last':events[-1] if events else None}
def pivot_ioc(events,value): return [e for e in events if value in {e.get('src_ip'),e.get('dst_ip'),e.get('hostname')}][:1000]
def pivot_host(events,ip): return [e for e in events if e.get('src_ip')==ip or e.get('dst_ip')==ip][:1000]
def explain_finding(finding): return {'name':finding.get('name'),'evidence':finding.get('evidence'),'reason':finding.get('reason'),'confidence':finding.get('confidence'),'score':finding.get('score')}
