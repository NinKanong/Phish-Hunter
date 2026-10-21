from __future__ import annotations
from collections import Counter
from math import log2

def shannon(value: str) -> float:
    if not value: return 0.0
    counts=Counter(value); n=len(value)
    return round(-sum((c/n)*log2(c/n) for c in counts.values()), 4)

def normalized_entropy(value: str) -> float:
    if not value or len(set(value)) <= 1: return 0.0
    return round(shannon(value) / max(1.0, log2(len(set(value)))), 4)
