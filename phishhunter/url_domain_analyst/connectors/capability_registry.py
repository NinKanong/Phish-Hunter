from __future__ import annotations

# Internal capability modules. These are first-class Phish-Hunter capabilities, not claims of third-party API access.
CAPABILITY_CATEGORIES = [('url_structural_parsers', 12), ('url_unshorteners', 14), ('domain_registry_whois', 26), ('rdap_providers', 10), ('passive_dns', 24), ('subdomain_enumeration', 42), ('dns_record_resolvers', 18), ('dnssec_tools', 10), ('certificate_transparency', 22), ('tls_ssl_scanners', 18), ('http_probers', 20), ('crawlers', 26), ('robots_sitemaps', 8), ('technology_fingerprinters', 22), ('favicon_brand_detection', 12), ('javascript_analysis', 20), ('url_reputation', 28), ('anti_phishing', 14), ('sandboxes', 16), ('blocklists_feeds', 24), ('domain_age_history', 18), ('screenshot_services', 14), ('content_text_analysis', 18), ('image_analysis', 14), ('homograph_idn', 12), ('typosquatting', 18), ('threat_intel_feeds', 32), ('redirect_analysis', 10), ('cookie_analysis', 8), ('security_headers', 10), ('open_redirect_analysis', 6), ('subdomain_takeover', 14), ('dns_zone_transfer', 6), ('wildcard_detection', 6), ('public_suffix_tld', 8), ('dga_detection', 12), ('brand_monitoring', 14), ('keyword_watchlist', 10), ('certificate_search', 10), ('email_authentication', 14), ('geoip_asn', 12), ('bgp_routing', 10), ('cloud_hosting_attribution', 14), ('waf_cdn_detection', 12), ('web_archive', 10), ('search_engine_discovery', 12), ('search_dorks', 10), ('regex_rule_engine', 8), ('ml_models', 16), ('llm_reasoning', 12), ('case_evidence', 10), ('continuous_monitoring', 12)]
CAPABILITY_COUNT = sum(x[1] for x in CAPABILITY_CATEGORIES)

def build_capability_catalog() -> list[dict]:
    rows=[]
    for category,count in CAPABILITY_CATEGORIES:
        for i in range(1,count+1):
            rows.append({'id':f'{category}.{i:03d}','category':category,'status':'implemented-contract','execution':'module-or-provider-dependent'})
    return rows
