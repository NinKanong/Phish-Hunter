from __future__ import annotations
from bs4 import BeautifulSoup
from typing import Any
from urllib.parse import urljoin


def analyze(html: str, base_url: str) -> dict[str,Any]:
    soup=BeautifulSoup(str(html or ''),'html.parser')
    title=(soup.title.get_text(' ',strip=True) if soup.title else '')[:500]
    forms=[]
    for form in soup.find_all('form')[:200]:
        forms.append({'action':urljoin(base_url,form.get('action') or base_url),'method':(form.get('method') or 'GET').upper(),'inputs':[{'name':x.get('name'),'type':x.get('type') or x.name} for x in form.find_all(['input','textarea','select'])[:100]]})
    resources=[]
    for tag,attr,kind in [('script','src','script'),('img','src','image'),('link','href','link'),('iframe','src','iframe')]:
        for node in soup.find_all(tag,attrs={attr:True})[:500]: resources.append({'kind':kind,'url':urljoin(base_url,node.get(attr))})
    metas={}
    for m in soup.find_all('meta')[:200]:
        key=m.get('name') or m.get('property')
        if key: metas[str(key).lower()]=m.get('content')
    return {'title':title,'forms':forms,'resources':resources,'meta':metas,'text_length':len(soup.get_text(' ',strip=True))}
