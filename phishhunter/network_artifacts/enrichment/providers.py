from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from phishhunter.config import settings

@dataclass(slots=True)
class Provider:
    key:str; label:str; environment_key:str
    def status(self):
        configured=bool(getattr(settings,self.environment_key,''))
        return {'provider':self.key,'label':self.label,'configured':configured,'execution':'available_when_configured' if configured else 'not_configured'}

PROVIDERS=[Provider('virustotal','VirusTotal','virustotal_api_key'),Provider('abuseipdb','AbuseIPDB','abuseipdb_api_key'),Provider('shodan','Shodan','shodan_api_key'),Provider('otx','AlienVault OTX','otx_api_key'),Provider('threatfox','ThreatFox','threatfox_api_key'),Provider('urlhaus','URLhaus','urlhaus_api_key'),Provider('misp','MISP','misp_api_key')]

def catalog(): return [p.status() for p in PROVIDERS]

def enrich(iocs):
    providers=catalog(); configured=[p for p in providers if p['configured']]
    ledger={}
    for kind,values in iocs.items():
        for value in values[:500]:
            key=f'{kind}:{value}'
            ledger[key]={'ioc':value,'type':kind,'status':'observed_only','providers':configured and [p['label'] for p in configured] or [],'reason':'Observed in uploaded evidence; no live reputation result is claimed by the local engine.'}
    return {'status':'connector_boundary','providers':providers,'results':{},'ledger':ledger,'ioc_count':sum(len(v) for v in iocs.values() if isinstance(v,list))}
