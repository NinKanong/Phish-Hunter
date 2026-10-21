from __future__ import annotations
from typing import Any

SECTIONS = [
    ('Domain Identity', 50, ['domain','unicode_domain','punycode','fqdn','registrable_domain','tld','sld','subdomain','label_count','label_entropy','idna_status','mixed_script','homograph_score','typosquat_score','dga_score','registration_age_days','registration_age_iso','registration_status','transfer_lock','update_lock','delete_lock','hold_status','renewal_status','registry_domain_id','registry_name','registry_url','rdap_url','whois_server','canonical_name','normalized_name','ascii_name','unicode_name','label_lengths','label_count','wildcard_status','wildcard_scope','dnssec_delegation','domain_category','domain_type','input_type','normalized_input','target_host','target_port','target_path','target_query','target_fragment','observed_at','collection_status','evidence_count']),
    ('Registrar Information', 40, ['name','iana_id','handle','accreditation','url','whois_server','rdap_server','country','abuse_email','abuse_phone','abuse_url','email','phone','address','city','state','postal_code','registrar_type','registrar_status','registrar_source','first_seen','last_seen','change_count','transfer_count','market_presence','trust_score','abuse_signal','privacy_service','reseller','reseller_handle','registry_relationship','source_count','consensus','confidence','observed_at','evidence_ids','normalized_name','normalized_country','contactability','provider_state']),
    ('Registry Information', 25, ['name','domain_id','whois_server','rdap_server','country','url','registry_type','since_year','tld_count','domain_count','status','dnssec_supported','registry_operator','iana_tld','tld_class','cc_tld','g_tld','registry_source','registry_observed_at','registry_confidence','registry_evidence','policy_url','abuse_url','support_url']),
    ('Registrant Contact', 60, ['name','organization','email','phone','fax','street','city','state','postal_code','country','contact_id','handle','roles','privacy_provider','privacy_reason','redaction_level','redacted_name','redacted_org','redacted_email','redacted_phone','redacted_address','contact_form','abuse_contact','historical_name','historical_org','historical_email','historical_phone','historical_country','historical_address','reverse_whois_count','reverse_whois_domains','reverse_whois_confidence','entity_type','legal_entity','jurisdiction','company_id','tax_id','incorporation_date','company_status','industry','sic_code','naics_code','employee_count','revenue','funding','investors','founders','executives','linkedin','website','social_profiles','related_domains','related_ips','related_asns','related_certs','related_emails','source_count','source_consensus','observed_at','evidence_ids','confidence','privacy_note']),
    ('Administrative Contact', 25, ['name','organization','email','phone','fax','street','city','state','postal_code','country','contact_id','handle','roles','privacy_provider','redaction_level','contact_form','abuse_contact','first_seen','last_seen','change_count','source_count','confidence','observed_at','evidence_ids']),
    ('Technical Contact', 25, ['name','organization','email','phone','country','contact_id','handle','roles','privacy_provider','redaction_level','contact_form','abuse_contact','first_seen','last_seen','change_count','source_count','confidence','observed_at','evidence_ids','mailbox_status','domain_scope','provider']),
    ('Billing Contact', 25, ['name','organization','email','phone','country','contact_id','handle','roles','privacy_provider','redaction_level','contact_form','first_seen','last_seen','change_count','source_count','confidence','observed_at','evidence_ids','billing_status','provider','domain_scope','redaction_reason','contactability','source']),
    ('Nameservers', 30, ['primary','secondary','count','provider','type','anycast','ipv4','ipv6','ttl','ttl_history','response_time','uptime','glue_records','glue_ipv4','glue_ipv6','ns_hostnames','ns_ips','ns_asns','ns_countries','ns_organizations','ns_first_seen','ns_last_seen','ns_changes','ns_consensus','dnssec','source_count','confidence','observed_at','evidence_ids','lifecycle']),
    ('DNS Configuration', 35, ['dnssec_enabled','dnssec_algorithm','dnssec_key_size','ds_records','dnskey_records','rrsig_records','nsec_records','nsec3_records','soa_mname','soa_rname','soa_serial','soa_refresh','soa_retry','soa_expire','soa_minimum','soa_ttl','caa_present','caa_issuers','caa_flags','wildcard','zone_transfer_status','axfr_observed','ixfr_observed','anycast','geo_dns','split_horizon','resolver_agreement','dane','tlsa','dmarc','spf','dkim','bimi','mta_sts','tls_rpt']),
    ('WHOIS History', 30, ['event_count','change_count','first_observed','last_observed','registration_event','expiration_event','update_event','transfer_event','nameserver_changes','registrar_changes','status_changes','registrant_changes','privacy_changes','contact_changes','change_frequency','stability_score','historical_registrars','historical_nameservers','historical_statuses','historical_contacts','historical_orgs','historical_emails','historical_countries','historical_sources','history_confidence','history_depth','history_start','history_end','evidence_count','timeline_link']),
    ('Corporate Information', 35, ['legal_entity','jurisdiction','company_id','registration_number','company_type','company_status','incorporated','industry','sic_code','naics_code','employees','revenue','funding','revenue_model','target_market','ceo','cto','ciso','founders','board','linkedin','website','hq_address','hq_city','hq_region','hq_country','offices','subsidiaries','parent_company','brands','products','press_mentions','patents','trademarks','corporate_confidence']),
    ('Related Entities', 50, ['related_domains','related_subdomains','related_ips','related_asns','related_netblocks','related_certs','related_emails','related_orgs','related_people','related_social_profiles','related_technologies','related_services','related_cves','related_threats','related_breaches','related_iocs','related_feeds','related_campaigns','reverse_ip','reverse_ns','reverse_mx','reverse_analytics','reverse_cert','reverse_favicon','shared_ga_id','shared_adsense_id','shared_favicon','shared_cert','shared_ip','shared_asn','shared_nameserver','shared_mx','shared_technology','shared_tracking','parent_domain','sibling_domains','child_domains','brand_domains','typosquat_domains','homograph_domains','punycode_variants','certificate_sans','ct_related_domains','pdns_related_domains','archive_related_urls','search_related_urls','code_related_repos','document_related_urls','image_related_urls','related_entity_count','relationship_confidence']),
    ('Evidence Sources', 50, ['rdap_sources','whois_sources','historical_sources','corporate_sources','dns_sources','ct_sources','pdns_sources','geo_sources','http_sources','tls_sources','reputation_sources','threat_sources','search_sources','archive_sources','code_sources','document_sources','social_sources','breach_sources','sandbox_sources','provider_count','source_count','unique_source_count','provider_backed_count','self_discovered_count','cross_verified_count','conflicting_count','missing_provider_count','coverage_score','consensus','provenance_status','evidence_first_seen','evidence_last_seen','evidence_hashes','evidence_ids','source_urls','collection_methods','collection_duration','provider_errors','rate_limit_events','timeout_events','retry_count','freshness','staleness','quality_score','confidence','observed_at','case_id','analyst_notes','legal_basis','retention_class']),
    ('Silent AI', 40, ['overall_summary','legitimacy_verdict','confidence','risk_assessment','trust_score','anomaly_status','recommendation','prediction_30d','prediction_90d','reasoning_step_1','reasoning_step_2','reasoning_step_3','reasoning_step_4','reasoning_step_5','reasoning_step_6','anomaly_dns','anomaly_registration','anomaly_infrastructure','anomaly_certificate','anomaly_content','anomaly_reputation','anomaly_behavior','cross_correlation_1','cross_correlation_2','cross_correlation_3','cross_correlation_4','cross_correlation_5','model_version','model_family','evidence_count','supporting_sources','contradicting_sources','uncertainty','explanation','next_action','review_priority','analyst_question','watch_recommendation','prediction_confidence','ai_status','ai_generated_at']),
]


def _flatten(obj: Any, prefix: str='') -> dict[str, Any]:
    out={}
    if isinstance(obj, dict):
        for k,v in obj.items():
            key=f'{prefix}.{k}' if prefix else str(k)
            if isinstance(v,(dict,list)):
                out.update(_flatten(v,key))
            else:
                out[key.lower()]=v
    elif isinstance(obj,list):
        for i,v in enumerate(obj[:100]):
            out.update(_flatten(v,f'{prefix}[{i}]'))
    return out


def build(domain_info: dict[str,Any], rdap: dict[str,Any]|None=None, result:dict[str,Any]|None=None) -> list[dict[str,Any]]:
    di=domain_info if isinstance(domain_info,dict) else {}
    flat=_flatten(di)
    if isinstance(rdap,dict): flat.update({f'rdap.{k}':v for k,v in _flatten(rdap).items()})
    if isinstance(result,dict):
        for k,v in _flatten(result).items():
            if k.startswith(('dns.','tls.','http.','certificate_posture.')): flat[k]=v
    fields=[]
    for section,count,names in SECTIONS:
        for i in range(count):
            base=names[i % len(names)]
            ordinal=(i//len(names))+1
            key=f'{section.lower().replace(" ","_")}.{base}' + (f'_{ordinal}' if ordinal>1 else '')
            candidates=[base.lower(),f'{section.lower()}.{base.lower()}',f'{section.lower().replace(" ","_")}.{base.lower()}']
            value=None; observed=False
            for c in candidates:
                if c in flat:
                    value=flat[c]; observed=value not in (None,'',[],{})
                    if observed: break
            if isinstance(value,(dict,list)):
                value=value
            fields.append({
                'id':key,'section':section,'field':base.replace('_',' ').title(),
                'value':value if observed else None,
                'status':'observed' if observed else 'not-observed',
                'source':'RDAP/registry' if observed and ('registr' in section.lower() or 'whois' in section.lower()) else ('correlated case evidence' if observed else 'provider-dependent'),
                'confidence':None if not observed else 'source-backed',
                'observed':observed,
                'ai':{'status':'evidence-grounded','insight':'Available' if observed else 'Awaiting supporting evidence','confidence':None,'anomaly':None,'prediction':None},
                'isolate':True,
            })
    return fields
