from __future__ import annotations

def diff_records(old: dict, new: dict) -> dict:
    def flat(d):
        return {str(k):str(v) for k,v in (d or {}).items()}
    a,b=flat(old),flat(new)
    return {"added":{k:b[k] for k in b.keys()-a.keys()},"removed":{k:a[k] for k in a.keys()-b.keys()},
            "changed":{k:{"old":a[k],"new":b[k]} for k in a.keys() & b.keys() if a[k]!=b[k]}}
