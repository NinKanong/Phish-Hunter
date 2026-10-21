from __future__ import annotations
import unicodedata
from typing import Iterable

SCRIPT_RANGES = {
    'latin': ((0x0041,0x024F),), 'greek': ((0x0370,0x03FF),),
    'cyrillic': ((0x0400,0x052F),), 'hebrew': ((0x0590,0x05FF),),
    'arabic': ((0x0600,0x06FF),), 'devanagari': ((0x0900,0x097F),),
    'cjk': ((0x3400,0x4DBF),(0x4E00,0x9FFF)),
}

def scripts(value: str) -> list[str]:
    found=set()
    for ch in value:
        cp=ord(ch)
        for name,ranges in SCRIPT_RANGES.items():
            if any(lo <= cp <= hi for lo,hi in ranges): found.add(name)
    return sorted(found)

def invisible_chars(value: str) -> list[str]:
    return [f'U+{ord(ch):04X}' for ch in value if unicodedata.category(ch) in {'Cf','Cc'} and ch not in '\t\n\r']

def normalized_forms(value: str) -> dict[str, str]:
    return {form:unicodedata.normalize(form, value) for form in ('NFC','NFD','NFKC','NFKD')}

def bidi_flags(value: str) -> list[str]:
    return sorted({unicodedata.bidirectional(ch) for ch in value if unicodedata.bidirectional(ch) in {'R','AL','RLO','RLE','LRO','LRE','PDF','LRI','RLI','FSI','PDI'}})
