from __future__ import annotations
from typing import Any
from urllib.parse import urlparse

KNOWN_SERVICES = {
    "google-analytics.com":("Google Analytics","analytics"),
    "googletagmanager.com":("Google Tag Manager","tag-manager"),
    "doubleclick.net":("Google/DoubleClick","advertising"),
    "facebook.net":("Meta/Facebook Pixel","analytics"),
    "connect.facebook.net":("Meta/Facebook Pixel","analytics"),
    "hubspot.com":("HubSpot","marketing"),
    "hs-scripts.com":("HubSpot","marketing"),
    "customer.io":("Customer.io","marketing"),
    "stripe.com":("Stripe","payments"),
    "paypal.com":("PayPal","payments"),
    "shopify.com":("Shopify","ecommerce"),
    "cdn.shopify.com":("Shopify CDN","ecommerce"),
    "cloudflare.com":("Cloudflare","cdn/security"),
    "amazonaws.com":("Amazon Web Services","cloud"),
    "azure.com":("Microsoft Azure","cloud"),
    "microsoftonline.com":("Microsoft identity infrastructure","identity"),
    "sentry.io":("Sentry","observability"),
    "datadoghq.com":("Datadog","observability"),
    "newrelic.com":("New Relic","observability"),
    "crowdstrike.com":("CrowdStrike","security"),
    "wazuh.com":("Wazuh","security"),
    "elastic.co":("Elastic","security/observability"),
    "splunk.com":("Splunk","security/observability"),
}


def build(result: dict[str, Any]) -> dict[str, Any]:
    rows=[]; seen=set()
    http=result.get("http") if isinstance(result.get("http"),dict) else {}
    headers={str(k).lower():str(v) for k,v in (http.get("headers") or {}).items()} if isinstance(http,dict) else {}
    artifacts=[]
    artifacts += [x.get("url") for x in (http.get("scripts") or []) if isinstance(x,dict) and x.get("url")]
    artifacts += [x.get("url") for x in (http.get("links") or []) if isinstance(x,dict) and x.get("url")]
    artifacts += [v for v in headers.values()]
    for tech in result.get("technology") or []:
        if isinstance(tech,dict):
            name=tech.get("technology") or tech.get("name")
            if name: artifacts.append(str(name))
    for raw in artifacts:
        if not isinstance(raw,str): continue
        low=raw.lower()
        for needle,(name,category) in KNOWN_SERVICES.items():
            if needle in low:
                key=(name,category,needle)
                if key in seen: continue
                seen.add(key)
                rows.append({"service":name,"category":category,"signal":needle,"source":"public HTTP/resource signal","confidence":78})
    w=result.get("wappalyzer") if isinstance(result.get("wappalyzer"),dict) else {}
    for item in w.get("technologies") or []:
        if not isinstance(item,dict): continue
        name=item.get("name");
        if not name: continue
        key=(name,"wappalyzer")
        if key in seen: continue
        seen.add(key)
        rows.append({"service":name,"category":"technology","signal":item.get("slug"),"version":(item.get("versions") or [None])[0],"source":"Wappalyzer","confidence":90})
    return {
        "status":"complete" if rows else "provider-dependent",
        "observations":rows[:1000],"count":len(rows),
        "publicly_observable":True,
        "internal_security_stack_status":"not-observable-from-passive-public-surface",
        "note":"Internal SIEM/EDR/firewall products are not inferred merely because a company uses security tooling. A row is emitted only when a public signal or authorized provider reports it.",
    }
