from __future__ import annotations
from typing import Any

STACKS={
 'SIEM':['Splunk','Microsoft Sentinel','Elastic SIEM','IBM QRadar','ArcSight','Wazuh','Sumo Logic','LogRhythm'],
 'EDR/XDR':['CrowdStrike Falcon','Microsoft Defender for Endpoint','SentinelOne','Sophos','Cortex XDR','Carbon Black'],
 'WAF/CDN':['Cloudflare','Akamai','Imperva','AWS WAF','Azure WAF','Fastly','F5'],
 'Identity':['Microsoft Entra ID','Okta','Ping Identity','Auth0','Keycloak'],
 'Observability':['Datadog','New Relic','Sentry','Elastic','Grafana','Prometheus'],
 'Payments':['Stripe','PayPal','Shopify Payments','Adyen','Checkout.com'],
 'Business/ERP':['SAP','Oracle','Microsoft Dynamics','Salesforce'],
 'Banking/Fintech':['BAKONG','NBC Bakong','Intellect','Temenos','Finacle','Mambu','Thought Machine'],
}

def build(result:dict[str,Any])->dict[str,Any]:
    http=result.get('http') if isinstance(result.get('http'),dict) else {}
    headers=' '.join(f'{k}:{v}' for k,v in (http.get('headers') or {}).items()).lower()
    artifacts=list(http.get('scripts') or [])+list(http.get('links') or [])
    corpus=headers+' '+' '.join(str(x.get('url') or '') for x in artifacts if isinstance(x,dict))
    for tech in result.get('technology') or []:
        if isinstance(tech,dict): corpus+=' '+str(tech.get('technology') or '')
    w=result.get('wappalyzer') if isinstance(result.get('wappalyzer'),dict) else {}
    for t in w.get('technologies') or []:
        if isinstance(t,dict): corpus+=' '+str(t.get('name') or '')
    corpus=corpus.lower()
    rows=[]
    for category, names in STACKS.items():
        for name in names:
            if name.lower() in corpus:
                rows.append({'category':category,'technology':name,'status':'publicly-observed','confidence':78,'evidence':'HTTP/resource/Wappalyzer surface'})
    return {'observations':rows,'count':len(rows),'categories':sorted(set(r['category'] for r in rows)),'internal_stack_visibility':'not_observable_without authorized telemetry','note':'A public technology signal cannot prove that a private SIEM, EDR, firewall model, ERP or security control is deployed internally.'}
