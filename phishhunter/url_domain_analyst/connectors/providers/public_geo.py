from __future__ import annotations
import ipaddress
from typing import Any

async def lookup_many(client, ips: list[str], limit: int=20) -> list[dict[str,Any]]:
    out=[]
    for raw in ips[:limit]:
        try:
            ip=ipaddress.ip_address(str(raw))
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved: continue
        except ValueError:
            continue
        for endpoint,source in ((f'https://ipwho.is/{ip}','ipwho.is'),(f'https://ipapi.co/{ip}/json/','ipapi.co'),(f'https://rdap.org/ip/{ip}','RDAP-IP')):
            try:
                r=await client.get(endpoint,headers={'Accept':'application/json'})
                if r.status_code != 200: continue
                data=r.json()
                if not isinstance(data,dict): continue
                if source=='ipwho.is' and data.get('success') is False: continue
                cc=data.get('country_code') or data.get('countryCode')
                if source=='RDAP-IP' and not cc:
                    ents=data.get('entities') if isinstance(data.get('entities'),list) else []
                    for ent in ents:
                        if isinstance(ent,dict) and ent.get('country'): cc=ent.get('country'); break
                if not cc: continue
                out.append({'ip':str(ip),'country_code':str(cc).upper(),'country':data.get('country') or cc,'city':data.get('city'),'region':data.get('region') or data.get('regionName'),'lat':data.get('latitude'),'lon':data.get('longitude'),'asn':data.get('connection',{}).get('asn') if isinstance(data.get('connection'),dict) else data.get('asn'),'organization':data.get('connection',{}).get('org') if isinstance(data.get('connection'),dict) else data.get('org'),'source':source,'precision':'provider-coordinate' if data.get('latitude') is not None else 'provider-country'})
                break
            except Exception:
                continue
    return out
