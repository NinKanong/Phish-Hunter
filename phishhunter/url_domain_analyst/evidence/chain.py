from __future__ import annotations
import hashlib, json

def summarize(result:dict)->dict:
    evidence=result.get('evidence') or []
    hashes=[]
    for i,ev in enumerate(evidence[:5000]):
        raw=json.dumps(ev,sort_keys=True,default=str,separators=(',',':'))
        hashes.append({'index':i,'sha256':hashlib.sha256(raw.encode()).hexdigest()})
    return {'artifact_count':len(hashes),'artifact_hashes':hashes,'package_sha256':(result.get('chain_of_custody') or {}).get('package_sha256'),'note':'Application integrity metadata; not a legal chain-of-custody determination.'}
