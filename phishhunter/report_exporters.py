from __future__ import annotations

import csv, io, json, html, hashlib, zipfile, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Callable

EXPORT_FORMATS = [
    ('docx','DOCX','application/vnd.openxmlformats-officedocument.wordprocessingml.document','docx'),('xlsx','XLSX','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','xlsx'),('pptx','PPTX','application/vnd.openxmlformats-officedocument.presentationml.presentation','pptx'),('json','JSON','application/json','json'),('json-min','JSON Minified','application/json','min.json'),
    ('json-ld','JSON-LD','application/ld+json','jsonld'),('xml','XML','application/xml','xml'),('yaml','YAML','text/yaml','yaml'),
    ('csv','CSV','text/csv','csv'),('tsv','TSV','text/tab-separated-values','tsv'),('markdown','Markdown','text/markdown','md'),
    ('txt','Plain Text','text/plain','txt'),('html','HTML','text/html','html'),('html-print','HTML Print','text/html','print.html'),
    ('stix','STIX 2.1','application/json','stix.json'),('misp-event','MISP Event','application/json','misp.json'),
    ('misp-attribute','MISP Attributes','application/json','misp-attributes.json'),('openioc','OpenIOC','application/xml','ioc.xml'),
    ('maec','MAEC','application/json','maec.json'),('sarif','SARIF','application/json','sarif.json'),('veris','VERIS','application/json','veris.json'),
    ('yara','YARA','text/plain','yar'),('sigma','Sigma','text/yaml','yml'),('suricata','Suricata','text/plain','rules'),('snort','Snort','text/plain','rules'),
    ('zeek','Zeek','text/plain','zeek'),('kql','KQL','text/plain','kql'),('spl','SPL','text/plain','spl'),('aql','AQL','text/plain','aql'),('eql','EQL','text/plain','eql'),
    ('blocklist-ip','IP Blocklist','text/plain','txt'),('blocklist-domain','Domain Blocklist','text/plain','txt'),
    ('graphml','GraphML','application/graphml+xml','graphml'),('gexf','GEXF','application/xml','gexf'),('dot','DOT','text/vnd.graphviz','dot'),('mermaid','Mermaid','text/plain','mmd'),
    ('mitre-navigator','MITRE Navigator','application/json','navigator.json'),('d3fend','MITRE D3FEND','application/json','d3fend.json'),('kill-chain','Kill Chain','application/json','killchain.json'),('diamond','Diamond Model','application/json','diamond.json'),
    ('cyclonedx','CycloneDX','application/json','cyclonedx.json'),('spdx','SPDX','application/json','spdx.json'),('openapi','OpenAPI','application/json','openapi.json'),('postman','Postman Collection','application/json','postman.json'),
    ('email-html','Email HTML','text/html','email.html'),('email-text','Email Text','text/plain','email.txt'),('slack','Slack Block Kit','application/json','slack.json'),('teams','Teams Adaptive Card','application/json','teams.json'),('discord','Discord Embed','application/json','discord.json'),('telegram','Telegram Markdown','text/markdown','telegram.md'),('webhook','Webhook JSON','application/json','webhook.json'),
]


def _json(scan): return json.dumps(scan, indent=2, sort_keys=True, default=str)
def _flat_iocs(scan):
    for kind, values in (scan.get('iocs') or {}).items():
        if isinstance(values, list):
            for v in values: yield kind, str(v)


def _yaml(scan):
    try:
        import yaml
        return yaml.safe_dump(scan, sort_keys=False, allow_unicode=True)
    except Exception:
        # Deterministic JSON is valid YAML 1.2 and keeps the exporter dependency-free.
        return _json(scan)


def _xml(scan):
    root=ET.Element('cyber-phish-k4-report')
    def walk(parent,key,value):
        if isinstance(value,dict):
            node=ET.SubElement(parent,'object',{'name':str(key)})
            for k,v in value.items(): walk(node,k,v)
        elif isinstance(value,list):
            node=ET.SubElement(parent,'array',{'name':str(key)})
            for i,v in enumerate(value): walk(node,str(i),v)
        else:
            ET.SubElement(parent,'value',{'name':str(key)}).text=str(value)
    for k,v in scan.items(): walk(root,k,v)
    return ET.tostring(root,encoding='unicode')


def _csv(scan, delimiter=','):
    out=io.StringIO(); w=csv.writer(out,delimiter=delimiter)
    w.writerow(['type','value'])
    for k,v in _flat_iocs(scan): w.writerow([k,v])
    return out.getvalue()


def _markdown(scan,title):
    lines=[f'# {title}','',f"Generated: {datetime.now(timezone.utc).isoformat()}",f"Verdict: **{scan.get('verdict','unknown')}**",f"Risk: **{scan.get('risk_score',0)}/100**",'', '## Findings']
    for f in scan.get('findings',[]): lines += [f"### {f.get('name','Finding')}",f"- Severity: {f.get('severity')}",f"- Confidence: {f.get('confidence')}",f"- What: {f.get('what_found')}",f"- Interpretation: {f.get('interpretation')}",f"- Evidence: {', '.join(f.get('raw_evidence_ids',[]))}",'']
    lines += ['## Raw Evidence','```json',_json(scan.get('raw_evidence',scan.get('evidence',[]))),'```','## IOC Inventory','```json',_json(scan.get('iocs',{})),'```','## Timeline','```json',_json(scan.get('timeline',[])),'```']
    return '\n'.join(lines)


def _html(scan,title,print_mode=False):
    body=[]
    for f in scan.get('findings',[]):
        body.append(f"<article><h3>{html.escape(str(f.get('name','Finding')))}</h3><p><b>{html.escape(str(f.get('severity')))}</b> · confidence {html.escape(str(f.get('confidence')))}</p><p>{html.escape(str(f.get('what_found')))}</p><p>{html.escape(str(f.get('interpretation')))}</p><pre>{html.escape(json.dumps(f.get('raw_evidence_ids',[])))}</pre></article>")
    return f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title><style>body{{font-family:system-ui;background:#050816;color:#dbeafe;max-width:1400px;margin:auto;padding:40px}}article{{border:1px solid #233047;border-radius:14px;padding:18px;margin:12px 0;background:#09101f}}pre{{white-space:pre-wrap;overflow:auto}}@media print{{body{{background:white;color:black}}article{{break-inside:avoid}}}}</style></head><body><h1>{html.escape(title)}</h1><p>Risk {scan.get('risk_score',0)}/100 · {html.escape(str(scan.get('verdict','unknown')))}</p>{''.join(body)}<h2>Raw evidence</h2><pre>{html.escape(_json(scan.get('raw_evidence',scan.get('evidence',[]))))}</pre></body></html>"


def _stix(scan,title):
    now=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    objects=[{'type':'report','spec_version':'2.1','id':'report--'+hashlib.sha256(title.encode()).hexdigest()[:32],'created':now,'modified':now,'name':title,'description':str(scan.get('executive_summary',''))}]
    for kind,value in _flat_iocs(scan):
        if kind in {'ipv4','ipv6','ips'}: pattern=f"[ipv4-addr:value = '{value}']" if ':' not in value else f"[ipv6-addr:value = '{value}']"
        elif kind=='domains': pattern=f"[domain-name:value = '{value}']"
        elif kind=='urls': pattern=f"[url:value = '{value.replace(chr(39), chr(92)+chr(39))}']"
        elif kind=='hashes' and len(value)==64: pattern=f"[file:hashes.'SHA-256' = '{value}']"
        elif kind=='hashes' and len(value)==40: pattern=f"[file:hashes.'SHA-1' = '{value}']"
        elif kind=='hashes' and len(value)==32: pattern=f"[file:hashes.MD5 = '{value}']"
        else: continue
        iid='indicator--'+hashlib.sha256(pattern.encode()).hexdigest()[:32]
        objects.append({'type':'indicator','spec_version':'2.1','id':iid,'created':now,'modified':now,'name':kind,'pattern_type':'stix','pattern':pattern,'valid_from':now})
    return json.dumps({'type':'bundle','id':'bundle--'+hashlib.sha256(title.encode()).hexdigest()[:32],'objects':objects},indent=2)


def _misp(scan,title):
    attrs=[]
    for kind,value in _flat_iocs(scan): attrs.append({'type':kind,'value':value,'to_ids':True,'comment':'Observed by Cyber-Phish-k4 analyzer'})
    return json.dumps({'Event':{'info':title,'threat_level_id':'2','analysis':'0','published':False,'Attribute':attrs}},indent=2)


def _sarif(scan,title):
    results=[]
    for f in scan.get('findings',[]): results.append({'ruleId':f.get('id'),'level':{'critical':'error','high':'error','medium':'warning','low':'note','info':'note'}.get(f.get('severity'),'note'),'message':{'text':str(f.get('what_found'))},'locations':[{'physicalLocation':{'artifactLocation':{'uri':str(f.get('source','analysis'))}}}]})
    return json.dumps({'version':'2.1.0','runs':[{'tool':{'driver':{'name':'Cyber-Phish-k4'}},'results':results}]},indent=2)


def _rules(scan, kind):
    lines=[]
    for f in scan.get('findings',[]):
        name=str(f.get('name','finding')).replace(' ','_').lower()
        iocs=[x.get('value') for x in f.get('related_iocs',[]) if isinstance(x,dict)]
        if kind=='yara': lines.append(f'rule K4_{name[:40]} {{\n strings:\n  $k4 = "{name[:32]}" nocase\n condition:\n  $k4\n}}')
        elif kind=='sigma': lines.append(f'title: K4 {name}\nid: {f.get("id")}\nstatus: experimental\nlogsource:\n  product: generic\ndetection:\n  selection:\n    message|contains: {name}\n  condition: selection\n')
        elif kind=='suricata':
            for v in iocs[:5]: lines.append(f'alert ip any any -> any any (msg:"K4 {name}"; content:"{v}"; sid:4000000;)')
        elif kind=='snort':
            for v in iocs[:5]: lines.append(f'alert ip any any -> any any (msg:"K4 {name}"; content:"{v}"; sid:4000000;)')
        elif kind=='zeek': lines.append(f'# K4 {f.get("id")} {name}')
    return '\n'.join(lines)+'\n'


def _graphml(scan):
    root=ET.Element('graphml',{'xmlns':'http://graphml.graphdrawing.org/xmlns'}); g=ET.SubElement(root,'graph',{'id':'K4','edgedefault':'directed'})
    nodes=[]
    for kind,value in _flat_iocs(scan):
        nid='n'+hashlib.sha1((kind+value).encode()).hexdigest()[:12]; nodes.append(nid); n=ET.SubElement(g,'node',{'id':nid}); ET.SubElement(n,'data',{'key':'value'}).text=value
    for a,b in zip(nodes,nodes[1:]): ET.SubElement(g,'edge',{'source':a,'target':b})
    return ET.tostring(root,encoding='unicode')


def _gexf(scan):
    root=ET.Element('gexf',{'xmlns':'http://gexf.net/1.2draft','version':'1.2'}); g=ET.SubElement(root,'graph',{'defaultedgetype':'directed'}); ns=ET.SubElement(g,'nodes'); es=ET.SubElement(g,'edges'); nodes=[]
    for kind,value in _flat_iocs(scan):
        nid='n'+hashlib.sha1((kind+value).encode()).hexdigest()[:12]; nodes.append(nid); ET.SubElement(ns,'node',{'id':nid,'label':value})
    for i,(a,b) in enumerate(zip(nodes,nodes[1:])): ET.SubElement(es,'edge',{'id':str(i),'source':a,'target':b})
    return ET.tostring(root,encoding='unicode')


def _dot(scan):
    nodes=[]
    for kind,value in _flat_iocs(scan):
        nid='n'+hashlib.sha1((kind+value).encode()).hexdigest()[:10]; nodes.append((nid,value))
    lines=['digraph K4 {']+[f'  {n} [label="{v.replace(chr(34),chr(92)+chr(34))}"];' for n,v in nodes]
    lines += [f'  {a} -> {b};' for (a,_),(b,_) in zip(nodes,nodes[1:])] + ['}']
    return '\n'.join(lines)


def _mermaid(scan):
    lines=['graph TD']
    nodes=[]
    for kind,value in _flat_iocs(scan):
        nid='N'+hashlib.sha1((kind+value).encode()).hexdigest()[:8]; nodes.append((nid,value)); lines.append(f'  {nid}["{value.replace(chr(34),"'")}"]')
    lines += [f'  {a} --> {b}' for (a,_),(b,_) in zip(nodes,nodes[1:])]
    return '\n'.join(lines)


def _navigator(scan):
    techniques=[]
    for x in scan.get('mitre_techniques',[]):
        if isinstance(x,dict) and x.get('id'): techniques.append(x['id'])
    return json.dumps({'name':'Cyber-Phish-k4 ATT&CK layer','versions':{'attack':'16','navigator':'5.1'},'domain':'enterprise-attack','techniques':[{'techniqueID':x,'score':1} for x in sorted(set(techniques))]},indent=2)


def _blocklist(scan,kind):
    vals=[]
    for k,v in _flat_iocs(scan):
        if (kind=='ip' and k in {'ips','ipv4','ipv6'}) or (kind=='domain' and k=='domains'): vals.append(v)
    return '\n'.join(sorted(set(vals)))+'\n'


def _structured(scan,kind,title):
    now=datetime.now(timezone.utc).isoformat()
    if kind=='veris': return json.dumps({'incident':{'incident_id':hashlib.sha256(title.encode()).hexdigest()[:16],'summary':scan.get('executive_summary'),'timeline':scan.get('timeline',[])}},indent=2)
    if kind=='maec': return json.dumps({'maec_version':'5.0','malware_subjects':[{'id':'K4-1','findings':scan.get('findings',[])}]},indent=2)
    if kind=='cyclonedx': return json.dumps({'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'metadata':{'timestamp':now},'components':[]},indent=2)
    if kind=='spdx': return json.dumps({'spdxVersion':'SPDX-2.3','creationInfo':{'created':now,'creators':['Tool: Cyber-Phish-k4']},'name':title},indent=2)
    if kind=='openapi': return json.dumps({'openapi':'3.0.3','info':{'title':'Cyber-Phish-k4 Report API','version':'1.0'},'paths':{'/reports/{id}':{'get':{'responses':{'200':{'description':'Report'}}}}}},indent=2)
    if kind=='postman': return json.dumps({'info':{'name':'Cyber-Phish-k4 Report API'},'item':[]},indent=2)
    if kind=='kill-chain': return json.dumps({'framework':'Lockheed Martin Cyber Kill Chain','observed_stages':scan.get('mitre_techniques',[]),'evidence':scan.get('raw_evidence',[])},indent=2)
    if kind=='diamond': return json.dumps({'adversary':{'confidence':'not asserted'},'infrastructure':scan.get('iocs',{}),'capabilities':scan.get('mitre_techniques',[]),'victim':[]},indent=2)
    if kind=='d3fend': return json.dumps({'version':'1.0','observations':[],'note':'Defensive mapping requires validated technique observations.'},indent=2)
    return _json(scan)


def export_report(fmt:str,title:str,scan:dict)->tuple[bytes,str,str]:
    fmt=fmt.lower().strip()
    if fmt in {'docx','xlsx','pptx'}:
        from phishhunter.report_office import docx, xlsx, pptx
        fn={'docx':docx,'xlsx':xlsx,'pptx':pptx}[fmt]
        payload=fn(title,scan); media={'docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','pptx':'application/vnd.openxmlformats-officedocument.presentationml.presentation'}[fmt]; ext=fmt
    elif fmt=='json': payload,media,ext=_json(scan).encode(),'application/json','json'
    elif fmt=='json-min': payload,media,ext=json.dumps(scan,separators=(',',':'),default=str).encode(),'application/json','min.json'
    elif fmt=='json-ld': payload,media,ext=json.dumps({'@context':'https://schema.org','@type':'Report','name':title,'about':scan},default=str,indent=2).encode(),'application/ld+json','jsonld'
    elif fmt=='xml': payload,media,ext=_xml(scan).encode(),'application/xml','xml'
    elif fmt=='yaml': payload,media,ext=_yaml(scan).encode(),'text/yaml','yaml'
    elif fmt=='csv': payload,media,ext=_csv(scan).encode(),'text/csv','csv'
    elif fmt=='tsv': payload,media,ext=_csv(scan,'\t').encode(),'text/tab-separated-values','tsv'
    elif fmt=='markdown': payload,media,ext=_markdown(scan,title).encode(),'text/markdown','md'
    elif fmt in {'txt','email-text','telegram'}: payload,media,ext=_markdown(scan,title).encode(),'text/plain','txt' if fmt=='txt' else ('txt' if fmt=='email-text' else 'md')
    elif fmt in {'html','html-print','email-html'}: payload,media,ext=_html(scan,title,fmt=='html-print').encode(),'text/html','html' if fmt=='html' else ('print.html' if fmt=='html-print' else 'email.html')
    elif fmt=='stix': payload,media,ext=_stix(scan,title).encode(),'application/json','stix.json'
    elif fmt in {'misp-event','misp-attribute'}: payload,media,ext=_misp(scan,title).encode(),'application/json','misp.json' if fmt=='misp-event' else 'misp-attributes.json'
    elif fmt in {'openioc'}: payload,media,ext=_xml({'title':title,'iocs':scan.get('iocs',{})}).encode(),'application/xml','ioc.xml'
    elif fmt in {'maec','veris','cyclonedx','spdx','openapi','postman','d3fend','kill-chain','diamond'}: payload,media,ext=_structured(scan,fmt,title).encode(),'application/json',fmt+'.json'
    elif fmt=='sarif': payload,media,ext=_sarif(scan,title).encode(),'application/json','sarif.json'
    elif fmt in {'yara','sigma','suricata','snort','zeek'}: payload,media,ext=_rules(scan,fmt).encode(),'text/plain',{'yara':'yar','sigma':'yml','suricata':'rules','snort':'rules','zeek':'zeek'}[fmt]
    elif fmt in {'kql','spl','aql','eql'}:
        values=[v for _,v in _flat_iocs(scan)][:100]
        payload=('\n'.join(f'// K4 IOC {v}' for v in values) or '// No IOC values were extracted.').encode(); media='text/plain'; ext=fmt
    elif fmt in {'blocklist-ip','blocklist-domain'}: payload,media,ext=_blocklist(scan,'ip' if fmt.endswith('ip') else 'domain').encode(),'text/plain','txt'
    elif fmt=='graphml': payload,media,ext=_graphml(scan).encode(),'application/graphml+xml','graphml'
    elif fmt=='gexf': payload,media,ext=_gexf(scan).encode(),'application/xml','gexf'
    elif fmt=='dot': payload,media,ext=_dot(scan).encode(),'text/vnd.graphviz','dot'
    elif fmt=='mermaid': payload,media,ext=_mermaid(scan).encode(),'text/plain','mmd'
    elif fmt=='mitre-navigator': payload,media,ext=_navigator(scan).encode(),'application/json','navigator.json'
    elif fmt=='slack': payload,media,ext=json.dumps({'blocks':[{'type':'section','text':{'type':'mrkdwn','text':f'*{title}*\nRisk: {scan.get("risk_score",0)}/100'}}]},indent=2).encode(),'application/json','slack.json'
    elif fmt=='teams': payload,media,ext=json.dumps({'type':'AdaptiveCard','version':'1.5','body':[{'type':'TextBlock','text':title},{'type':'TextBlock','text':f'Risk: {scan.get("risk_score",0)}/100'}]},indent=2).encode(),'application/json','teams.json'
    elif fmt=='discord': payload,media,ext=json.dumps({'embeds':[{'title':title,'description':str(scan.get('executive_summary',''))}]},indent=2).encode(),'application/json','discord.json'
    elif fmt=='webhook': payload,media,ext=json.dumps({'event':'k4.report.generated','title':title,'scan':scan},default=str).encode(),'application/json','webhook.json'
    else: raise ValueError(f'Unsupported report format: {fmt}')
    return payload,media,ext


def bundle_all(title:str,scan:dict,pdf_bytes:bytes|None=None)->bytes:
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        for fmt,_,_,ext in EXPORT_FORMATS:
            try:
                payload,_,real_ext=export_report(fmt,title,scan)
                z.writestr(f'report_{fmt}.{real_ext}',payload)
            except Exception as exc:
                z.writestr(f'EXPORT_{fmt}_ERROR.txt',f'Exporter error: {exc}')
        if pdf_bytes: z.writestr('report.pdf',pdf_bytes)
        z.writestr('MANIFEST.json',json.dumps({'title':title,'format_count':len(EXPORT_FORMATS)+bool(pdf_bytes),'generated_at':datetime.now(timezone.utc).isoformat()},indent=2))
    return out.getvalue()
