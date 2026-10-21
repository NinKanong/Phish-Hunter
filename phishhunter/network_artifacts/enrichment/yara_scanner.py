from __future__ import annotations
from pathlib import Path

def scan(data:bytes,rules_dir:str='data/yara-rules')->dict:
    try:
        import yara  # type: ignore
    except Exception:
        return {'status':'unavailable','matches':[],'reason':'yara-python is not installed in this runtime'}
    rules=list(Path(rules_dir).rglob('*.yar'))+list(Path(rules_dir).rglob('*.yara'))
    if not rules:return {'status':'no_rules','matches':[]}
    matches=[]
    for rule in rules[:100]:
        try:
            compiled=yara.compile(filepath=str(rule)); matches.extend([{'rule':m.rule,'tags':m.tags,'source':str(rule)} for m in compiled.match(data=data,timeout=5)])
        except Exception: continue
    return {'status':'scanned','matches':matches[:1000],'rules_considered':min(len(rules),100)}
