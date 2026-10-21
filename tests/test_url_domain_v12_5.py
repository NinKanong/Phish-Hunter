from __future__ import annotations
import json
from phishhunter.analyzers.unified_url_domain import _parse_dns_answers, _record_dict, _rdap_entities, _rdap_events, _reputation_summary
from phishhunter.url_domain_analyst.domain.public_suffix import split_registered_domain
from phishhunter.url_domain_analyst.url.encoding_layers import detect_encoding_layers, bounded_url_decode
from phishhunter.url_domain_analyst.technology.security_stack import build as build_stack
from phishhunter.url_domain_analyst.workforce.intelligence import build as build_workforce
import pytest


def test_malformed_dns_and_rdap_payloads_never_raise():
    assert _parse_dns_answers('bad') == []
    assert _record_dict(['bad', {'name':'x.','type':1,'ttl':60,'value':'1.2.3.4'}], 'A') == [{'name':'x.','ttl':60,'value':'1.2.3.4'}]
    assert _rdap_entities({'entities':['bad',{'roles':['registrar'],'vcardArray':['vcard',[]]}]})
    assert _rdap_events({'events':['bad',{'eventAction':'registration','eventDate':'2025-01-01'}]}) == [{'event_action':'registration','date':'2025-01-01','actor':None}]


def test_provider_reputation_payloads_are_type_safe():
    x=_reputation_summary('bad',['bad'],{'matches':'bad'},{'results':['bad']},'bad')
    assert isinstance(x,dict) and x['signals']==[]


def test_global_suffix_and_encoding():
    x=split_registered_domain('login.example.co.uk')
    assert x['registered_domain']=='example.co.uk'
    assert any(y['technique']=='double-encoding' for y in detect_encoding_layers('%252e%252e%252f'))
    assert len(bounded_url_decode('%2520'))>=2


def test_security_stack_only_reports_observed_signals():
    r=build_stack({'http':{'headers':{'server':'nginx'},'scripts':[{'url':'https://www.googletagmanager.com/gtm.js'}]},'technology':[{'technology':'Splunk'}], 'wappalyzer':{'technologies':[]}})
    names={x['technology'] for x in r['observations']}
    assert 'Splunk' in names
    assert all(x['status']=='publicly-observed' for x in r['observations'])


def test_workforce_export_boundary():
    w=build_workforce(domain='example.com',wappalyzer={'company':{'company_size':'SIZE_5'}},linkedin={'people':[{'firstName':'A','lastName':'B','headline':'Analyst','member':'urn:li:person:x'}]})
    assert w['employee_size_range']=='201-500 employees'
    assert w['employee_observation_count']==1


@pytest.mark.asyncio
async def test_full_analyzer_survives_malformed_provider_shapes(monkeypatch):
    import phishhunter.analyzers.unified_url_domain as mod

    async def dns_bundle(_):
        return {'records': {'A':['bad', {'name':'x','ttl':60,'value':'1.2.3.4'}], 'NS':['bad'], 'TXT':['bad']}, 'reverse_dns': {'1.2.3.4':['bad']}, 'resolver':'test'}
    async def auth_bundle(*_): return {}
    async def rdap(*_): return {'status':200,'url':'test','data':{'nameservers':['ns1.example'], 'events':['bad',{'eventAction':'registration','eventDate':'2025-01-01'}], 'entities':['bad',{'roles':['registrar'],'vcardArray':['vcard',[]]}]}}
    async def ct(*_): return {'count':1,'names':['www.example.com'],'certificates':[{'id':'c1','common_name':'example.com','name_value':'example.com\nwww.example.com'}]}
    async def http_probe(*_): return {'status':'completed','status_code':200,'final_url':'https://example.com/','headers':{},'redirects':[],'forms':['bad',{'action':'https://example.com/login','fields':[]}],'links':['bad',{'url':'https://example.com','external':False}],'scripts':['https://example.com/app.js'],'content_length':10,'resolutions':[]}
    async def empty(*_): return {'status':'not_configured'}
    async def dnsdump(*_): return {'status':'completed','records':['bad']}
    async def hibp(*_): return {'status':'no_results','records':'bad','breached_identity_count':0}
    async def gsb(*_): return {'status':'completed','matches':'bad'}
    async def vt(*_): return {'status':'completed','last_analysis_stats':'bad'}
    async def urlscan(*_): return {'status':'completed','results':'bad'}
    async def abuse(*_): return {'results':['bad']}
    monkeypatch.setattr(mod,'_dns_bundle',dns_bundle)
    monkeypatch.setattr(mod,'_dns_auth_bundle',auth_bundle)
    monkeypatch.setattr(mod,'_rdap',rdap)
    monkeypatch.setattr(mod,'_ct_lookup',ct)
    monkeypatch.setattr(mod,'_http_probe',http_probe)
    monkeypatch.setattr(mod,'_gsb_url',gsb)
    monkeypatch.setattr(mod,'_vt_domain',vt)
    monkeypatch.setattr(mod,'_urlscan_search',urlscan)
    monkeypatch.setattr(mod,'_hibp_domain',hibp)
    monkeypatch.setattr(mod,'_dnsdumpster',dnsdump)
    monkeypatch.setattr(mod,'_abuseipdb',abuse)
    monkeypatch.setattr(mod,'_ssl_probe',lambda *_: {'status':'not_configured'})
    monkeypatch.setattr(mod,'tool_fabric_status',lambda: {'items':[]})
    result=await mod.analyze_url_domain('example.com')
    assert isinstance(result,dict)
    assert result['domain']=='example.com'
    assert result['whois_rdap']['name_servers']==['ns1.example']
    assert result['verdict'] in {'low-risk','suspicious','high-risk','critical'}
