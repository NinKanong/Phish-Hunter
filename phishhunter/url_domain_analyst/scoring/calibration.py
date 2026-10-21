from __future__ import annotations

def calibrate(risk:dict)->dict:
    score=max(0,min(100,int(risk.get('score',0) or 0)))
    band='critical' if score>=85 else 'high' if score>=65 else 'medium' if score>=35 else 'low'
    return {'score':score,'band':band,'confidence_interval':[max(0,score-10),min(100,score+10)],'method':'rule-weighted calibration with explicit uncertainty band'}
