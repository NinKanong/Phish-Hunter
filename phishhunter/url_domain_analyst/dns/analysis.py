from __future__ import annotations
from collections import defaultdict
import re

DNS_TYPES=['A','AAAA','CNAME','DNAME','NS','PTR','MX','TXT','SOA','SRV','NAPTR','CAA','DS','DNSKEY','RRSIG','NSEC','NSEC3','CDS','CDNSKEY','TLSA','SSHFP','SMIMEA','BIMI','MTA-STS','TLS-RPT','HTTPS','SVCB','LOC','RP','URI','CERT','DHCID','HIP','IPSECKEY','KEY','SIG','WKS','ATMA','APL','EUI48','EUI64','CSYNC','ZONEMD','OPENPGPKEY','AFSDB','MD','MF','MB','MG','MR','NULL']

def _values(records: dict, rtype: str) -> list[dict]:
    return list(records.get(rtype,[]) or [])

def parse_spf(txt: list[dict]) -> dict:
    vals=[x.get('value','') for x in txt if str(x.get('value','')).lower().startswith('v=spf1')]
    out={'present':bool(vals),'records':vals,'mechanisms':[],'qualifiers':{},'lookup_count':0,'void_lookup_count':0,'permerror_candidate':False}
    if vals:
        toks=vals[0].split()[1:]
        for t in toks:
            q=t[0] if t[:1] in '+-~?' else '+'
            term=t[1:] if t[:1] in '+-~?' else t
            if term.startswith(('include:','a','mx','ptr','exists:','redirect=')): out['lookup_count']+=1
            out['mechanisms'].append(term); out['qualifiers'][term]=q
        out['permerror_candidate']=out['lookup_count']>10
    return out

def parse_dmarc(txt: list[dict]) -> dict:
    vals=[x.get('value','') for x in txt if str(x.get('value','')).lower().startswith('v=dmarc1')]
    tags={}
    if vals:
        for pair in vals[0].split(';'):
            if '=' in pair:
                k,v=pair.strip().split('=',1); tags[k]=v
    return {'present':bool(vals),'record':vals[0] if vals else None,'tags':tags,'policy':tags.get('p'),'subdomain_policy':tags.get('sp'),'pct':tags.get('pct')}

def parse_txt_auth(records: dict) -> dict:
    txt=_values(records,'TXT')
    auth={'spf':parse_spf(txt),'dmarc':parse_dmarc(txt),'dkim_selector_hints':[],
          'bimi':any(str(x.get('value','')).lower().startswith('v=bimi1') for x in txt),
          'mta_sts':any('v=stsv1' in str(x.get('value','')).lower() for x in txt),
          'tls_rpt':any('v=tlsrptv1' in str(x.get('value','')).lower() for x in txt)}
    for row in txt:
        val=str(row.get('value',''))
        if 'v=dkim1' in val.lower() or 'p=' in val and 'k=' in val: auth['dkim_selector_hints'].append(val[:220])
    return auth

def analyze(bundle: dict|None) -> dict:
    bundle=bundle or {}; records=bundle.get('records',{}) or {}
    by_type={k:_values(records,k) for k in DNS_TYPES}
    ttl_values=[x.get('ttl') for rows in by_type.values() for x in rows if isinstance(x.get('ttl'),int)]
    ips=[x.get('value') for t in ('A','AAAA') for x in by_type[t] if x.get('value')]
    ns=[x.get('value') for x in by_type['NS'] if x.get('value')]
    mx=[x.get('value') for x in by_type['MX'] if x.get('value')]
    return {'supported_record_types':DNS_TYPES,'records':by_type,'current_ips':ips,'nameservers':ns,'mail_exchangers':mx,
      'ttl_summary':{'count':len(ttl_values),'min':min(ttl_values) if ttl_values else None,'max':max(ttl_values) if ttl_values else None,
                     'unique':sorted(set(ttl_values)) if ttl_values else []},
      'dns_authentication':parse_txt_auth(records),
      'dnssec':{'dnskey':by_type['DNSKEY'],'ds':by_type['DS'],'rrsig':by_type['RRSIG'],'nsec':by_type['NSEC'],'nsec3':by_type['NSEC3'],'tlsa':by_type['TLSA'],
                'enabled':bool(by_type['DNSKEY'] or by_type['DS'])},
      'advanced':{'wildcard_detection':'not_observed_without_controlled negative-name probes','zone_transfer':'not_attempted by passive web service','split_horizon':'provider-dependent',
                  'geo_dns':'provider-dependent','anycast':'heuristic/provider-dependent','failover':'record-pattern dependent'},
      'resolution_modes':['recursive','authoritative','iterative','DoH','DoT','DoQ','DoH3','DNSCrypt','ODoH'],
    }
