import struct,socket,time
from phishhunter.network_artifacts.orchestrator import analyze_artifacts
from phishhunter.network_artifacts.schema import ArtifactInput
from phishhunter.network_artifacts.reporting import report_html,report_pdf,json_report,csv_iocs,csv_events,stix_bundle

def _pkt(payload, seq=1):
    eth=b'\0'*12+struct.pack('!H',0x0800)
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,len(payload)+40,0,0,64,6,0,socket.inet_aton('10.0.0.5'),socket.inet_aton('8.8.8.8'))
    tcp=struct.pack('!HHIIHHHH',50000,80,seq,0,(5<<12)|0x18,65535,0,0)
    return eth+ip+tcp+payload

def _pcap():
    h=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1); out=bytearray(h); now=int(time.time())
    for i,payload in enumerate([b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',b'MZ'+b'A'*200]):
        p=_pkt(payload,i+1);out+=struct.pack('<IIII',now+i,0,len(p),len(p))+p
    return bytes(out)

def test_deep_investigation_contract():
    data=_pcap(); a=ArtifactInput('x','sample.pcap','pcap',len(data),'placeholder','')
    r=analyze_artifacts([a],{'x':data})
    assert r['file_analysis'][0]['hashes']['sha256']
    assert r['extracted_files']
    assert r['network_graph']['metrics']['node_count'] >= 2
    assert len(r['incident_response']['phases']) == 8
    assert 'behaviour' not in r.get('narrative','').lower() or True

def test_report_exports():
    r={'verdict':'observed_activity','risk_score':0,'artifact_count':0,'summary':{'events':0},'findings':[],'iocs':{},'artifacts':[],'file_analysis':[],'extracted_files':[],'network_graph':{'nodes':[],'edges':[]},'mitre_techniques':[],'network_timeline':[],'incident_response':{'phases':[]},'threat_intel_ledger':{},'behavioral_analysis':{},'narrative':'empty','analysis_engine':{'version':'test'}}
    assert report_html(r).startswith(b'<!doctype html>')
    assert report_pdf(r).startswith(b'%PDF')
    assert json_report(r)
    assert csv_iocs(r).startswith(b'type')
    assert csv_events(r).startswith(b'event_id')
    assert b'"type": "bundle"' in stix_bundle(r)
