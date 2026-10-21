from __future__ import annotations

def normalize(provider_results:dict|None) -> dict:
    provider_results=provider_results or {}; rows=[]
    for name,data in provider_results.items():
        data=data or {}; status=str(data.get('status') or 'unknown')
        rows.append({'provider':name,'status':status,'configured':status in {'completed','live-configured'},
                     'positive':bool(data.get('malicious') or data.get('detections') or data.get('flagged')),
                     'confidence':float(data.get('confidence',0) or 0) if str(data.get('confidence','')).replace('.','',1).isdigit() else 0})
    positives=sum(1 for x in rows if x['positive']); configured=sum(1 for x in rows if x['configured'])
    consensus=round(100*positives/max(1,configured),1)
    return {'providers':rows,'configured_count':configured,'positive_count':positives,'consensus_pct':consensus,
            'verdict':'flagged' if positives>=2 else ('single-provider-signal' if positives==1 else 'no-consensus'),
            'false_positive_control':'Do not treat a single provider hit as attribution or compromise evidence.'}
