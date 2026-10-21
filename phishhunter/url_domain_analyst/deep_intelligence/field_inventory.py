from __future__ import annotations

def build(result: dict)->dict:
    dns=result.get('dns') if isinstance(result.get('dns'),dict) else {}
    records=dns.get('records') if isinstance(dns.get('records'),dict) else {}
    http=result.get('http') if isinstance(result.get('http'),dict) else {}
    tls=result.get('tls') if isinstance(result.get('tls'),dict) else {}
    rdap=result.get('whois_rdap') if isinstance(result.get('whois_rdap'),dict) else {}
    return {
      'url_fields': [
        'scheme','userinfo','host','registered_domain','port','path','query','fragment',
        'normalized_url','encoded_layers','decoded_path','query_parameters','tracking_parameters',
        'secret_parameter_flags','unicode_flags','obfuscation_flags','entropy','length','similarity_hash'
      ],
      'domain_fields': [
        'fqdn','registrable_domain','tld','sld','subdomain','label_count','label_entropy',
        'idna','punycode','mixed_script','homograph','typosquat_score','dga_score','domain_age_days','registrar'
      ],
      'observed_counts': {
        'dns_records': sum(len(x) for x in records.values() if isinstance(x,list)),
        'http_headers': len(http.get('headers') or {}),
        'tls_san': len(tls.get('san') or []),
        'rdap_entities': len(rdap.get('entities') or []),
      },
      'collection_coverage': 'source-backed; unavailable providers remain explicitly marked'
    }
