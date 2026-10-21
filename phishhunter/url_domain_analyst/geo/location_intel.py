from __future__ import annotations
from collections import Counter, defaultdict
from typing import Any
from .world_index import COUNTRY_INDEX, layers as world_layers

COUNTRY_NAMES = {
    'US':'United States','IE':'Ireland','IN':'India','CA':'Canada','GB':'United Kingdom','DE':'Germany',
    'FR':'France','NL':'Netherlands','SG':'Singapore','JP':'Japan','AU':'Australia','HK':'Hong Kong',
    'SE':'Sweden','CH':'Switzerland','FI':'Finland','NO':'Norway','DK':'Denmark','BR':'Brazil',
}
COUNTRY_CENTERS = {
    'US':(39.8,-98.6),'IE':(53.4,-8.0),'IN':(22.6,79.0),'CA':(56.1,-106.3),'GB':(55.4,-3.4),
    'DE':(51.2,10.4),'FR':(46.2,2.2),'NL':(52.1,5.3),'SG':(1.35,103.8),'JP':(36.2,138.3),
    'AU':(-25.3,133.8),'HK':(22.3,114.2),'SE':(62.0,15.0),'CH':(46.8,8.2),'FI':(64.0,26.0),
    'NO':(64.6,11.0),'DK':(56.2,9.5),'BR':(-10.8,-51.9),
}

def _country_name(code: str|None) -> str:
    code=(code or '').upper().strip()
    return COUNTRY_NAMES.get(code) or str(COUNTRY_INDEX.get(code, {}).get('name') or code or 'Unknown')

def _walk(obj: Any, path: str=''):
    if isinstance(obj, dict):
        for k,v in obj.items():
            yield path+'.'+str(k).lower() if path else str(k).lower(), v
            yield from _walk(v, path+'.'+str(k).lower() if path else str(k).lower())
    elif isinstance(obj, list):
        for i,v in enumerate(obj):
            yield from _walk(v, f'{path}[{i}]')

def build(result: dict[str, Any]) -> dict[str, Any]:
    country_counts: Counter[str]=Counter()
    provider_rows=[]
    points=[]
    networks=Counter()
    hosting=[]
    dnsdumpster=(result.get('dnsdumpster') or {}).get('records') or {}
    # AbuseIPDB exposes countryCode and ISP when configured.
    for row in ((result.get('provider_results') or {}).get('AbuseIPDB') or {}).get('results') or []:
        cc=row.get('countryCode') or row.get('country')
        if cc:
            name=_country_name(str(cc))
            country_counts[name]+=1
            provider_rows.append({'ip':row.get('ip'),'country_code':cc,'country':name,'isp':row.get('isp'),'source':'AbuseIPDB'})
            if row.get('isp'): networks[str(row['isp'])]+=1
    # Best-effort extraction from provider payloads. Coordinates are accepted only when
    # the provider actually returned numeric values; the UI never invents coordinates.
    for path,val in _walk(dnsdumpster):
        if isinstance(val, dict):
            ip=val.get('ip') or val.get('address')
            lat=val.get('lat') or val.get('latitude')
            lon=val.get('lon') or val.get('lng') or val.get('longitude')
            cc=val.get('country_code') or val.get('countryCode') or val.get('country')
            asn=val.get('asn') or val.get('as_number')
            owner=val.get('asn_name') or val.get('organization') or val.get('owner') or val.get('network')
            if owner and isinstance(owner,str): networks[owner]+=1
            if cc and isinstance(cc,str):
                name=_country_name(cc)
                country_counts[name]+=1
                provider_rows.append({'ip':ip,'country_code':cc,'country':name,'asn':asn,'organization':owner,'source':'DNSDumpster'})
            try:
                if ip and lat is not None and lon is not None:
                    latf=float(lat); lonf=float(lon)
                    if -90<=latf<=90 and -180<=lonf<=180:
                        points.append({'ip':str(ip),'lat':latf,'lon':lonf,'country':_country_name(cc),'asn':asn,'organization':owner,'source':'DNSDumpster'})
            except (TypeError,ValueError):
                pass
            if owner and (val.get('netblock') or val.get('cidr')):
                hosting.append({'organization':owner,'netblock':val.get('netblock') or val.get('cidr'),'ip':ip,'source':'DNSDumpster'})
    # Provider-reported country can be visualized at a country centroid only when exact coordinates are absent.
    # These points are explicitly tagged as country-level approximation, not host geolocation.
    surface = ((result.get('url_domain_vnext') or {}).get('attack_surface') if isinstance(result.get('url_domain_vnext'), dict) else None)
    surface_observations=[]
    if isinstance(surface, dict):
        for row in surface.get('a_records') or []:
            if isinstance(row,dict) and (row.get('country') or row.get('country_code')):
                surface_observations.append(row)
        for country_row in surface.get('countries') or []:
            if not isinstance(country_row, dict):
                continue
            name=str(country_row.get('country') or '').strip()
            code=str(country_row.get('country_code') or '').upper().strip()
            if not code:
                for k,v in COUNTRY_NAMES.items():
                    if v.lower()==name.lower(): code=k
            if code in COUNTRY_CENTERS and not any(p.get('country_code') == code for p in points):
                lat, lon = COUNTRY_CENTERS[code]
                points.append({'lat':lat,'lon':lon,'country':COUNTRY_NAMES.get(code,name),'country_code':code,'source':'attack-surface-country-observation','precision':'country-centroid','count':country_row.get('count',0),'note':'Country-level visualization only; not an exact host coordinate.'})
    wapp = result.get('wappalyzer') if isinstance(result.get('wappalyzer'), dict) else {}
    cc = wapp.get('ip_country')
    if isinstance(cc, str) and cc.upper() in COUNTRY_CENTERS and not any(p.get('country_code') == cc.upper() for p in points):
        lat, lon = COUNTRY_CENTERS[cc.upper()]
        points.append({'lat':lat,'lon':lon,'country':_country_name(cc),'country_code':cc.upper(),'source':'Wappalyzer','precision':'country-centroid','note':'Country-level visualization only; not an exact host coordinate.'})
    public_geo = result.get('ip_geolocation') if isinstance(result.get('ip_geolocation'), list) else []
    for row in public_geo:
        if not isinstance(row,dict): continue
        cc=str(row.get('country_code') or '').upper()
        if cc:
            name=_country_name(cc); country_counts[name]+=1
            provider_rows.append({'ip':row.get('ip'),'country_code':cc,'country':name,'city':row.get('city'),'region':row.get('region'),'asn':row.get('asn'),'organization':row.get('organization'),'source':row.get('source','public-geo')})
            try:
                lat=float(row.get('lat')); lon=float(row.get('lon'))
                if -90<=lat<=90 and -180<=lon<=180:
                    points.append({'lat':lat,'lon':lon,'country':name,'country_code':cc,'city':row.get('city'),'ip':row.get('ip'),'asn':row.get('asn'),'organization':row.get('organization'),'source':row.get('source','public-geo'),'precision':'provider-coordinate'})
            except (TypeError,ValueError):
                pass
    # A complete country index lets the UI render and highlight any ISO country returned by a provider.
    layer_rows=[]
    for row in surface_observations + public_geo + provider_rows:
        if isinstance(row,dict): layer_rows.append(row)
    country_layers=world_layers(layer_rows)

    return {
        'status':'complete' if (country_counts or points or networks or hosting) else 'provider-dependent',
        'countries': [{'country':k,'count':v} for k,v in country_counts.most_common()],
        'hosting_networks':[{'name':k,'count':v} for k,v in networks.most_common(24)],
        'provider_rows':provider_rows[:250],
        'map_points':points[:100],
        'country_layers':country_layers[:250],
        'country_index_size':len(COUNTRY_INDEX),
        'netblocks':hosting[:250],
        'world_summary': f'{len(country_counts)} countries / {sum(country_counts.values())} provider observations' if country_counts else 'No geolocated provider observations yet',
        'method':'Only provider-returned geolocation/network fields are displayed; no location is inferred from model knowledge.'
    }
