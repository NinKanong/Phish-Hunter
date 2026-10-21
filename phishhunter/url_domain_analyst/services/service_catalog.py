from __future__ import annotations
from typing import Any

SERVICE_CATEGORIES={
    "web": ["nginx","Apache","Microsoft-IIS","LiteSpeed","Caddy"],
    "proxy_cdn": ["Cloudflare","CloudFront","Fastly","Akamai","Varnish","Imperva"],
    "framework": ["Next.js","React","Vue","Angular","Django","Laravel","Rails","Express","Spring"],
    "cms": ["WordPress","Drupal","Joomla","Magento","Shopify"],
    "analytics": ["Google Analytics","Matomo","Hotjar","Amplitude","HubSpot"],
    "identity": ["Okta","Microsoft Entra","Auth0","Keycloak"],
    "security": ["Cloudflare WAF","AWS WAF","Imperva WAF","ModSecurity","Wordfence"],
    "monitoring": ["Datadog","New Relic","Sentry","Splunk","Elastic"],
    "business": ["Salesforce","SAP","Oracle","ServiceNow"],
}

def categorize(name: str) -> str:
    q=str(name or "").lower()
    for category,values in SERVICE_CATEGORIES.items():
        if any(v.lower() in q for v in values): return category
    return "other"

def normalize(row: Any) -> dict[str,Any]:
    row=row if isinstance(row,dict) else {}
    name=str(row.get("product") or row.get("service") or row.get("server") or "Unknown").strip()
    out=dict(row); out["category"]=categorize(name); out["display_name"]=name
    return out
