def build_summary(scan:dict)->str:
    return f"Verdict={scan.get('verdict','unknown')}; risk={scan.get('risk_score',0)}; IOC counts={ {k:len(v) for k,v in scan.get('iocs',{}).items()} }"
