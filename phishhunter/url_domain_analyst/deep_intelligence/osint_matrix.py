from __future__ import annotations

def build(domain:str, ips:list[str]|None=None)->dict:
    ips=ips or []
    return {'pivots':[
      {'type':'search','query':f'"{domain}"','purpose':'public references'},
      {'type':'search','query':f'site:{domain}','purpose':'indexed assets'},
      {'type':'search','query':f'site:{domain} filetype:pdf','purpose':'public documents'},
      {'type':'search','query':f'site:{domain} inurl:login','purpose':'authentication pages'},
      {'type':'certificate','query':f'hostname:{domain}','purpose':'certificate relationships'},
      {'type':'identity','query':f'"@{domain}"','purpose':'public organization/email references'},
      *[{'type':'ip','query':f'{ip}','purpose':'IP infrastructure pivot'} for ip in ips[:20]],
    ], 'safety':'Use provider APIs and public sources according to their terms; queries do not imply a finding.'}
