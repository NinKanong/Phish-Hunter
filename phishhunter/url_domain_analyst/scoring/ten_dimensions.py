from __future__ import annotations

def score(result:dict)->dict:
    url=result.get('url_forensics',{}); domain=result.get('domain_overview',{}); dns=result.get('dns_posture',{})
    http=result.get('http_posture',{}); tls=result.get('tls',{}); rep=result.get('reputation',{})
    dims={
      'structural': min(100,int(url.get('obfuscation',{}).get('score',0))),
      'domain': min(100, 70 if domain.get('idn') and domain.get('mixed_scripts') else 0),
      'dns': min(100, 40 if not dns.get('dnssec',{}).get('enabled') else 0),
      'infrastructure': min(100, int(result.get('infrastructure',{}).get('risk_score',0) or 0)),
      'certificate': min(100, 60 if tls.get('weak_protocol') or tls.get('certificate_expired') else 0),
      'content': min(100, 40 if http.get('cross_origin_form_actions') else 0),
      'visual': 0,
      'reputation': min(100, int(rep.get('consensus_pct',0) or 0)),
      'behavioral': 0,
      'correlation': min(100, 30 if result.get('graph',{}).get('edge_count',0)>20 else 0),
    }
    weights={'structural':.12,'domain':.10,'dns':.08,'infrastructure':.10,'certificate':.10,'content':.12,'visual':.08,'reputation':.15,'behavioral':.07,'correlation':.08}
    total=round(sum(dims[k]*weights[k] for k in dims),1)
    verdict='critical' if total>=85 else 'high' if total>=65 else 'medium' if total>=35 else 'low'
    return {'score':total,'verdict':verdict,'dimensions':dims,'weights':weights,'top_signals':sorted(dims.items(),key=lambda x:x[1],reverse=True)[:10],
            'method':'weighted evidence model; not a probability of compromise'}
