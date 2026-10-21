from __future__ import annotations
from collections import Counter
import math

def score(label: str) -> dict:
    s=''.join(c.lower() for c in str(label or '') if c.isalnum())
    if not s:return {'score':0,'signals':[]}
    counts=Counter(s); n=len(s); entropy=-sum((v/n)*math.log2(v/n) for v in counts.values())
    vowels=sum(c in 'aeiou' for c in s)/n
    digits=sum(c.isdigit() for c in s)/n
    score=0; sig=[]
    if n>=12 and entropy>=3.7: score+=35; sig.append('high-entropy')
    if digits>=.25: score+=20; sig.append('digit-heavy')
    if vowels<.15 or vowels>.65: score+=15; sig.append('unusual-vowel-ratio')
    return {'score':min(100,score),'entropy':round(entropy,3),'digit_ratio':round(digits,3),'vowel_ratio':round(vowels,3),'signals':sig,'family':'generic-dga-heuristic' if score>=35 else None}
