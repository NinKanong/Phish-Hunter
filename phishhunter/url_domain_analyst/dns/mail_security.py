from __future__ import annotations
import re
from typing import Any


def analyze(records: dict[str,Any]) -> dict[str,Any]:
    r=records if isinstance(records,dict) else {}
    txt=[str(x.get('value') or '') for x in (r.get('TXT') or []) if isinstance(x,dict)]
    spf=[x for x in txt if re.search(r'(?i)^v=spf1\\b',x.strip())]
    dmarc=[x for x in txt if re.search(r'(?i)^v=dmarc1\\b',x.strip())]
    return {
      'spf':{'present':bool(spf),'records':spf[:50],'lookup_mechanisms':sum(len(re.findall(r'(?i)(include:|redirect=|a:|mx:|exists:)',x)) for x in spf)},
      'dmarc':{'present':bool(dmarc),'records':dmarc[:50],'policy':next((re.search(r'(?i)\\bp=([^; ]+)',x).group(1) for x in dmarc if re.search(r'(?i)\\bp=([^; ]+)',x)),None)},
      'selectors':{'default':bool(r.get('DKIM-default'))},
      'mta_sts':bool(r.get('MTA-STS')),
      'tls_rpt':bool(r.get('TLS-RPT')),
    }
