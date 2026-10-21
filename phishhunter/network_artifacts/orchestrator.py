from __future__ import annotations
from collections import Counter, defaultdict
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from phishhunter.analyzers.pcap.analyzer import analyze_pcap
from phishhunter.analysis.deep_enhance import enhance_result

from .schema import ArtifactInput
from .detection import build_findings, build_summary
from .correlation.engine import correlate
from .ai.agent_controller import NetworkArtifactAgentController
from .ai.mitre_mapper import map_events
from .ai.narrative_builder import build as build_narrative
from .analyzers.pcap.deep_capture import deep_pcap_capture
from .analyzers.behavioral.beacon_detector import detect as detect_beacons
from .analyzers.behavioral.exfil_detector import detect as detect_exfil
from .analyzers.behavioral.lateral_detector import detect as detect_lateral
from .analyzers.behavioral.scan_detector import detect as detect_scans
from .analyzers.behavioral.arp_analyzer import detect as detect_arp
from .analyzers.dns.tunnel_detector import detect as detect_dns_tunnels
from .analyzers.dns.dga_detector import detect as detect_dga
from .analyzers.graph.network_graph import build as build_graph
from .analyzers.graph.graph_metrics import metrics as graph_metrics
from .analyzers.identity.victim_identifier import identify as identify_victims
from .analyzers.identity.attacker_identifier import classify as identify_external_sources
from .analyzers.identity.asset_profiler import profile as profile_assets
from .analyzers.tls.ja4_analyzer import fingerprint_tls
from .analyzers.tls.cert_analyzer import analyze_certificates
from .analyzers.tls.cipher_analyzer import analyze_ciphers
from .enrichment import enrich
from .incident_response.workflow import build_incident_response
from .parsers import parse_log, parse_netflow, parse_suricata, parse_zeek
from .utils.file_utils import static_profile

Progress = Callable[[int, str], None]


def detect_type(filename: str, data: bytes) -> str:
    name = filename.lower()
    if data[:4] in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"} or name.endswith((".pcap", ".pcapng", ".cap")):
        return "pcap"
    if "eve" in name or "suricata" in name:
        return "suricata"
    if "zeek" in name or name.endswith(("conn.log", "dns.log", "http.log", "ssl.log", "smb.log", "kerberos.log")):
        return "zeek"
    if "netflow" in name or "ipfix" in name or name.endswith(".flow.csv"):
        return "netflow"
    for kind in ("firewall", "proxy", "dns", "dhcp"):
        if kind in name:
            return kind
    return "firewall"


def _packet_message(packet: dict[str, Any]) -> str:
    parts=[]
    if packet.get("http") and (packet["http"].get("request_line") or packet["http"].get("host")):
        parts.append(str(packet["http"].get("request_line") or f"HTTP host {packet['http'].get('host')}"))
    if packet.get("tls_sni"): parts.append(f"TLS SNI: {packet['tls_sni']}")
    if packet.get("dns"):
        qs=[str(x.get('name')) for x in packet['dns'].get('questions',[]) if x.get('name')]
        if qs:parts.append("DNS: "+", ".join(qs[:5]))
    flags=[n.upper() for n,v in (packet.get('tcp_flags') or {}).items() if v]
    if flags:parts.append("TCP "+"/".join(flags))
    return " | ".join(parts)[:4000]


def _events_from_artifact(artifact: ArtifactInput, data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if artifact.artifact_type == "pcap":
        result=analyze_pcap(data)
        events=[]
        for packet in result.get("sample_packets") or []:
            events.append({'timestamp':packet.get('timestamp'),'source':'pcap','event_type':'packet','src_ip':packet.get('src'),'src_port':packet.get('sport'),'dst_ip':packet.get('dst'),'dst_port':packet.get('dport'),'protocol':packet.get('protocol'),'hostname':(packet.get('tls_sni') or (packet.get('http') or {}).get('host')),'bytes':packet.get('length'),'message':_packet_message(packet),'raw':packet})
        for flow in result.get('flows') or []:
            host=(flow.get('tls_sni') or [None])[0] if flow.get('tls_sni') else (flow.get('http_hosts') or [None])[0]
            events.append({'timestamp':flow.get('first_seen'),'source':'pcap','event_type':'flow','src_ip':flow.get('src'),'src_port':flow.get('sport'),'dst_ip':flow.get('dst'),'dst_port':flow.get('dport'),'protocol':flow.get('protocol'),'hostname':host,'bytes':flow.get('bytes'),'packets':flow.get('packets'),'message':f"{flow.get('packets',0)} packets / {flow.get('bytes',0)} bytes",'raw':flow})
        deep=deep_pcap_capture(data)
        return events, {'pcap_summary':result,'deep_capture':deep}
    text=data.decode('utf-8','replace')
    if artifact.artifact_type=='zeek': parsed=[x.as_dict() for x in parse_zeek(text,artifact.filename)]
    elif artifact.artifact_type=='suricata': parsed=[x.as_dict() for x in parse_suricata(text)]
    elif artifact.artifact_type=='netflow': parsed=[x.as_dict() for x in parse_netflow(text)]
    else: parsed=[x.as_dict() for x in parse_log(text,artifact.artifact_type,artifact.filename)]
    return parsed, {'record_count':len(parsed)}


def _collect_iocs(events, artifacts, extracted_files):
    out=defaultdict(set)
    for e in events:
        for key in ('src_ip','dst_ip'):
            v=e.get(key)
            if v: out['ips'].add(str(v))
        h=e.get('hostname')
        if h: out['domains'].add(str(h).rstrip('.'))
        raw=e.get('raw') or {}
        for ioc_key in ('ips','ipv4','ipv6','urls','domains','hashes','emails'):
            for v in raw.get(ioc_key,[]) if isinstance(raw.get(ioc_key),list) else []: out[ioc_key].add(str(v))
        if raw.get('payload_iocs'):
            for k,vals in raw['payload_iocs'].items():
                for v in vals or []: out[k].add(str(v))
    for a in artifacts: out['hashes'].add(a.sha256)
    for f in extracted_files:
        for k,v in (f.get('hashes') or {}).items(): out['hashes'].add(v)
    return {k:sorted(v)[:5000] for k,v in out.items()}


def _protocol_analysis(events, pcap_deep):
    counts=Counter(str(e.get('protocol') or 'unknown') for e in events)
    ports=Counter(int(e['dst_port']) for e in events if isinstance(e.get('dst_port'),int))
    return {'protocol_counts':dict(counts.most_common(50)),'top_destination_ports':dict(ports.most_common(100)),'pcap':pcap_deep or {},'protocol_notes':[
        'Protocol counts are observations from parsed records.',
        'Encrypted application content is not decrypted by this service.',
        'TLS fingerprint/certificate fields are populated only when raw handshake evidence supports them.'
    ]}



def _file_triage_profile(profile: dict[str, Any], *, source: str = "artifact") -> dict[str, Any]:
    entropy=float(profile.get("entropy") or 0)
    keywords=list(profile.get("suspicious_keywords") or [])
    indicators=profile.get("indicators") or {}
    indicator_count=sum(len(v) for v in indicators.values() if isinstance(v, list))
    score=8
    reasons=[]
    if entropy >= 7.5:
        score += 22; reasons.append("very high entropy")
    elif entropy >= 7.0:
        score += 14; reasons.append("high entropy")
    if profile.get("suspicious_extension"):
        score += 20; reasons.append("suspicious extension")
    if keywords:
        score += min(25, len(keywords)*6); reasons.append(f"{len(keywords)} suspicious keyword signal(s)")
    if indicator_count:
        score += min(15, indicator_count*2); reasons.append(f"{indicator_count} embedded indicator(s)")
    ftype=str(profile.get("type") or profile.get("kind") or "")
    if re.search(r"PE|ELF|executable|script|macro|pdf", ftype, re.I):
        score += 8; reasons.append("executable/script-like content")
    score=min(100, round(score))
    tier="critical" if score>=80 else "high" if score>=60 else "review" if score>=30 else "low"
    return {"risk_score":score,"risk_tier":tier,"triage_reasons":reasons,"triage_source":source,"triage_status":"suspicious_candidate" if score>=60 else "review_candidate" if score>=30 else "low_priority"}

def analyze_artifacts(artifacts: list[ArtifactInput], blobs: dict[str, bytes], progress: Progress|None=None, job_id:str='local')->dict[str,Any]:
    progress=progress or (lambda _p,_m:None)
    controller=NetworkArtifactAgentController(job_id,progress)
    controller.step('triage',2,'Evidence triage plan created',controller.plan())
    all_events=[]; artifact_results=[]; file_analysis=[]; pcap_deep={}; extracted_files=[]
    for index,artifact in enumerate(artifacts,1):
        progress(int((index-1)/max(1,len(artifacts))*45),f'Parsing {artifact.filename}')
        blob=blobs[artifact.artifact_id]
        events,detail=_events_from_artifact(artifact,blob)
        all_events.extend(events)
        if artifact.artifact_type=='pcap':
            pcap_deep=detail.get('deep_capture') or {}
            carved=pcap_deep.get('extracted_files') or []
            for carved_file in carved:
                prof=carved_file.get('profile') or {}
                carved_file.update(_file_triage_profile(prof, source='passive-carving'))
                # Keep the normalized static fields alongside the original profile so the UI
                # can triage recovered files without losing provenance.
                for key in ('type','mime','entropy','strings_count','strings_sample','indicators','suspicious_extension','suspicious_keywords'):
                    if key not in carved_file and key in prof:
                        carved_file[key]=prof[key]
            extracted_files.extend(carved)
        profile=static_profile(blob,artifact.filename)
        fp={'artifact_id':artifact.artifact_id,'filename':artifact.filename,'artifact_type':artifact.artifact_type,'hashes':profile['hashes'],'size_bytes':len(blob),'type':profile['type'],'mime':profile['mime'],'entropy':profile['entropy'],'strings_count':profile['strings_count'],'strings_sample':profile['strings_sample'],'indicators':profile['indicators'],'suspicious_extension':profile['suspicious_extension'],'suspicious_keywords':profile['suspicious_keywords']}
        fp.update(_file_triage_profile(profile, source='uploaded-artifact'))
        file_analysis.append(fp)
        artifact_results.append({'artifact':{'artifact_id':artifact.artifact_id,'filename':artifact.filename,'artifact_type':artifact.artifact_type,'size_bytes':artifact.size_bytes,'sha256':artifact.sha256,'path':artifact.path},'event_count':len(events),'detail':detail})
    controller.step('artifact_parsing',50,'All artifact families parsed',artifact_results)
    progress(55,'Correlating evidence across artifact families')
    correlation=correlate(all_events)
    controller.step('correlation',58,'Cross-artifact correlation complete',correlation)
    findings=build_findings(all_events)
    progress(62,'Running behavioral detections')
    behavioral={
      'beaconing_candidates':detect_beacons(all_events),
      'exfiltration_candidates':detect_exfil(all_events),
      'lateral_movement_candidates':detect_lateral(all_events),
      'scan_candidates':detect_scans(all_events),
      'arp_analysis':detect_arp(all_events),
      'dns_tunneling_candidates':detect_dns_tunnels(pcap_deep.get('dns_observations',[])),
      'dga_candidates':detect_dga([e.get('hostname') for e in all_events if e.get('hostname')]),
    }
    # Convert high-value behavioral candidates into findings while preserving source evidence.
    for item in behavioral['beaconing_candidates'][:100]: findings.append({'name':'Potential periodic beaconing','severity':'medium','confidence':item.get('confidence',50),'score':55,'reason':item.get('reason'),'evidence':item})
    for item in behavioral['dns_tunneling_candidates'][:100]: findings.append({'name':'DNS tunneling candidate','severity':'medium','confidence':item.get('confidence',55),'score':50,'reason':item.get('reason'),'evidence':item})
    for item in behavioral['lateral_movement_candidates'][:100]: findings.append({'name':f"Potential lateral movement via {item.get('service')}",'severity':'medium','confidence':item.get('confidence',55),'score':45,'reason':item.get('reason'),'evidence':item})
    controller.step('behavioral_detection',66,'Behavioral detection suite complete',behavioral)
    progress(70,'Profiling assets and network identities')
    victims=identify_victims(all_events); external_sources=identify_external_sources(all_events); assets=profile_assets(all_events)
    controller.step('identity_profiling',72,'Asset and source profiles complete',{'victims':len(victims),'external_sources':len(external_sources),'assets':len(assets)})
    graph=build_graph(all_events); graph['metrics']=graph_metrics(graph)
    iocs=_collect_iocs(all_events,artifacts,extracted_files)
    mitre=map_events(all_events,findings)
    tls=fingerprint_tls(pcap_deep.get('tls_observations',[])); certs=analyze_certificates(pcap_deep.get('tls_observations',[])); ciphers=analyze_ciphers(pcap_deep.get('tls_observations',[]))
    progress(78,'Preparing threat-intelligence ledger')
    intel=enrich(iocs)
    controller.step('threat_intel',80,'Threat-intelligence ledger prepared',intel)
    controller.step('mitre_mapping',82,'MITRE ATT&CK candidate mapping complete',mitre)
    summary=build_summary(all_events,findings)
    summary['risk_score']=min(100,max([int(x.get('score',0) or 0) for x in findings] or [0]))
    summary['top_findings']=sorted(findings,key=lambda x:int(x.get('score',0) or 0),reverse=True)[:20]
    summary['file_candidates']=len(extracted_files)
    network_assessment={
      'potential_compromised_hosts':[],
      'potential_c2_candidates':behavioral['beaconing_candidates'][:100],
      'external_attacker_candidates':external_sources[:100],
      'dns_tunneling_candidates':behavioral['dns_tunneling_candidates'][:100],
      'lateral_movement_candidates':behavioral['lateral_movement_candidates'][:100],
    }
    verdict='review_required' if findings else 'observed_activity'
    result={
      'analysis_engine':{'name':'K4 Network Artifacts Deep Investigation Engine','version':'15.0.0','execution':'passive','payload_execution':False},
      'service':'pcap-analyst','workspace':'network-artifacts','artifact_count':len(artifacts),'artifact_types':sorted({a.artifact_type for a in artifacts}),
      'artifacts':artifact_results,'file_analysis':file_analysis,'extracted_files':extracted_files[:200],'events':all_events[:20000],
      'suspicious_file_candidates':sorted([*file_analysis,*extracted_files],key=lambda x:int(x.get('risk_score',0) or 0),reverse=True)[:100],
      'findings':findings[:2000],'iocs':iocs,'network_graph':graph,'summary':summary,'correlation':correlation,'mitre_techniques':mitre,
      'network_timeline':[{'event_id':f'EV-{i+1:06d}','timestamp':e.get('timestamp'),'event_type':e.get('event_type'),'source':e.get('source'),'src_ip':e.get('src_ip'),'src_port':e.get('src_port'),'dst_ip':e.get('dst_ip'),'dst_port':e.get('dst_port'),'protocol':e.get('protocol'),'hostname':e.get('hostname'),'message':e.get('message'),'evidence_ref':e.get('raw',{})} for i,e in enumerate(all_events[:10000])],
      'timeline':[], 'raw_evidence':{'events':all_events[:5000],'artifacts':artifact_results},
      'network_assessment':network_assessment,'external_sources':external_sources[:200], 'victim_profiles':victims[:500], 'asset_profiles':assets[:500],
      'protocol_analysis':_protocol_analysis(all_events,pcap_deep),'tls_analysis':tls,'certificate_analysis':certs,'cipher_analysis':ciphers,'behavioral_analysis':behavioral,
      'threat_intel_ledger':intel.get('ledger',{}),'enrichment':intel,'risk_score':summary['risk_score'],'verdict':verdict,
    }
    result['timeline']=result['network_timeline']
    result['incident_response']=build_incident_response(result)
    result['narrative']=build_narrative(result)
    controller.step('incident_response',88,'Incident-response workflow generated',result['incident_response'])
    result['agent_controller']=controller.investigate(result)
    result['network_artifact_contract']={'siblings':['PCAP','PCAPNG','Zeek','Suricata','NetFlow/IPFIX','Firewall','Proxy','DNS','DHCP'],'correlation':['PCAP ↔ Zeek','NetFlow ↔ Suricata','IP ↔ hostname','IOC ↔ threat intelligence'],'execution':'No uploaded payload is executed by this service.','attribution':'Not inferred from network evidence alone.','forensic_workflow':['triage','attack_graph','victim_profile','kill_chain','behavioral_forensics','threat_intelligence','packet_drilldown','response','reporting'],'evidence_principles':['source_hashing','bounded_parsing','reproducible_observations','hypothesis_vs_fact_separation','analyst_disposition']}
    result['forensic_quality']={'source_artifacts':len(artifacts),'hashed_artifacts':sum(1 for a in artifacts if a.sha256),'raw_event_cap':5000,'timeline_cap':10000,'packet_drilldown':'bounded read-only','attribution_guardrail':True}
    result['case_metadata']={'case_id':job_id,'engine_version':'22.0.0','analysis_mode':'passive','created_at':datetime.now(timezone.utc).isoformat()}
    result=enhance_result(result,'pcap-analyst','network-artifacts')
    progress(100,'Deep network investigation complete')
    return result
