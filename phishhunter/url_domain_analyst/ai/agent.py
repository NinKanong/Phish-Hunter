from __future__ import annotations

def task_plan(result:dict) -> list[dict]:
    score=float(result.get('risk',{}).get('score',0) or 0); tasks=[]
    tasks.append({'priority':1,'task':'Verify primary infrastructure pivots','evidence':['DNS','RDAP','CT','IP'],'reason':'Anchor the case in independently sourced observations.'})
    tasks.append({'priority':2,'task':'Review URL obfuscation and redirect chain','evidence':['URL forensics','HTTP'],'reason':'Determine whether the target uses evasion or redirection signals.'})
    tasks.append({'priority':3,'task':'Correlate shared infrastructure','evidence':['IPs','NS','MX','certificates','technologies'],'reason':'Identify reusable infrastructure without inferring ownership.'})
    tasks.append({'priority':4,'task':'Cross-check threat intelligence and breach exposure','evidence':['reputation','breach providers'],'reason':'Require provider provenance and timestamp consistency.'})
    tasks.append({'priority':5,'task':'Preserve evidence and export case package','evidence':['ledger','graph','raw provider responses'],'reason':'Maintain chain-of-custody before remediation decisions.'})
    if score>=65: tasks.insert(0,{'priority':0,'task':'Escalate for senior analyst review','evidence':['risk dimensions'],'reason':'Elevated score warrants corroboration before response actions.'})
    return tasks

def evidence_grounded_prompt(result:dict)->str:
    return ('You are a defensive SOC investigation copilot. Use only supplied observations. Separate observed facts, '
            'correlated relationships, hypotheses and verification gaps. Never invent breach records, dark-web access, '
            'ownership, compromise or attribution. Recommend safe defensive validation steps.')
