from __future__ import annotations
import re

def analyze(html_sample:str|None)->dict:
    text=str(html_sample or '')
    scripts=re.findall(r'<script[^>]+src=[\"\']([^\"\']+)',text,re.I)
    forms=re.findall(r'<form[^>]+action=[\"\']([^\"\']+)',text,re.I)
    endpoints=sorted(set(re.findall(r'https?://[^\"\'\s<>]+',text)))
    return {'script_sources':scripts[:200],'form_actions':forms[:100],'embedded_urls':endpoints[:500],
            'secret_patterns':{'api_key_like':bool(re.search(r'api[_-]?key\s*[:=]',text,re.I)),'jwt_like':bool(re.search(r'eyJ[a-zA-Z0-9_-]{10,}\.',text))},
            'execution':'static-only'}
