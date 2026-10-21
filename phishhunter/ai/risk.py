def heuristic_risk(features:dict)->dict:
    score=min(100,int(sum(float(v) for v in features.values() if isinstance(v,(int,float)))))
    return {"score":score,"label":"high" if score>=60 else "medium" if score>=30 else "low"}
