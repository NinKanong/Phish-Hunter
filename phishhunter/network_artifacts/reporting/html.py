from __future__ import annotations
import html, json
from typing import Any


def _e(v): return html.escape(str(v if v is not None else ""))

def _table(rows, headers):
    head=''.join(f'<th>{_e(x)}</th>' for x in headers)
    body=''.join('<tr>'+''.join(f'<td>{_e(v)}</td>' for v in row)+'</tr>' for row in rows)
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body or "<tr><td colspan=\"%d\">No records</td></tr>"%len(headers)}</tbody></table></div>'

def _graph_svg(graph):
    nodes=(graph or {}).get('nodes',[])[:80]; edges=(graph or {}).get('edges',[])[:120]
    pos={n.get('id'):(60+(i%10)*105,70+(i//10)*75) for i,n in enumerate(nodes)}
    lines=[]
    for e in edges:
        a=pos.get(e.get('source')); b=pos.get(e.get('target'))
        if a and b: lines.append(f'<line stroke="#37516a" stroke-width="1" x1="{a[0]}" y1="{a[1]}" x2="{b[0]}" y2="{b[1]}"/>')
    circles=[]
    for n in nodes:
        p=pos[n.get('id')]; cls='public' if n.get('scope')=='public' else 'private'
        circles.append(f'<g><circle class="{cls}" fill="#102538" stroke="#4ab9ff" stroke-width="1.5" cx="{p[0]}" cy="{p[1]}" r="18"/><text x="{p[0]}" y="{p[1]+4}">{_e(str(n.get("id"))[-14:])}</text><title>{_e(n.get("id"))}</title></g>')
    return f'<svg class="graph" viewBox="0 0 1100 700">{"".join(lines)}{"".join(circles)}</svg>'

def report_html(result:dict[str,Any])->bytes:
    summary=result.get('summary') or {}; findings=result.get('findings') or []; files=result.get('file_analysis') or []; extracted=result.get('extracted_files') or []
    artifacts=result.get('artifacts') or []; iocs=result.get('iocs') or {}; mitre=result.get('mitre_techniques') or []; timeline=result.get('network_timeline') or []
    behavioral=result.get('behavioral_analysis') or {}; ir=result.get('incident_response') or {}; graph=result.get('network_graph') or {}
    finding_rows=[(f.get('name'),f.get('severity'),f.get('confidence'),f.get('score'),f.get('reason')) for f in findings[:250]]
    file_rows=[]
    for f in files+extracted[:100]:
        h=f.get('hashes') or {}; file_rows.append((f.get('filename'),f.get('type') or f.get('kind'),f.get('size_bytes') or f.get('size'),h.get('md5'),h.get('sha1'),h.get('sha256') or f.get('sha256'),f.get('entropy')))
    ioc_rows=[(k,v) for k,vals in iocs.items() for v in vals[:500]]
    mitre_rows=[(m.get('technique_id'),m.get('name'),m.get('tactic'),m.get('confidence'),m.get('basis')) for m in mitre[:200]]
    event_rows=[(e.get('timestamp'),e.get('source'),e.get('event_type'),e.get('src_ip'),e.get('dst_ip'),e.get('dst_port'),e.get('protocol'),e.get('message')) for e in timeline[:1000]]
    phases=''.join(f'<section><h3>{_e(p.get("phase"))}</h3><p>{_e(p.get("purpose"))}</p><span class="tag">{_e(p.get("status"))}</span></section>' for p in ir.get('phases',[]))
    generated=result.get('analysis_engine',{}).get('version','unknown')
    doc=f'''<!doctype html><html><head><meta charset="utf-8"><title>K4 Network Artifacts Investigation</title><style>
body{{font-family:Inter,Arial,sans-serif;background:#071019;color:#dbe8f5;margin:0;padding:0}}.wrap{{max-width:1500px;margin:auto;padding:35px}}header{{padding:30px 0 20px;border-bottom:1px solid #23384c}}h1{{font-size:32px;margin:0 0 8px}}h2{{margin-top:32px;border-bottom:1px solid #203447;padding-bottom:8px}}h3{{margin:12px 0 5px}}p{{color:#94a8bc;line-height:1.65}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.metric,section,.panel{{background:#0b1622;border:1px solid #203447;border-radius:12px;padding:15px;margin:10px 0}}.metric strong{{display:block;font-size:28px;margin-top:7px}}.metric span,.tag{{font-size:10px;color:#7590a8}}table{{width:100%;border-collapse:collapse}}th,td{{padding:9px;border-bottom:1px solid #1a2a3b;text-align:left;font-size:10px;vertical-align:top}}th{{color:#7ca2c3}}code{{color:#8bd6ff;overflow-wrap:anywhere}}.risk{{font-size:40px;font-weight:900}}.high{{color:#ff6b7a}}.medium{{color:#ffc65c}}.good{{color:#50dba5}}.graph{{width:100%;height:700px;background:#050b11;border:1px solid #203447}}.graph line{{stroke:#37516a;stroke-width:1}}.graph circle{{fill:#102538;stroke:#4ab9ff;stroke-width:1.5}}.graph circle.public{{fill:#35141d;stroke:#ff6372}}.graph text{{fill:#c9d9e8;font-size:9px}}.cols{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}.pre{{white-space:pre-wrap;background:#050a10;padding:15px;border-radius:9px;color:#9ab0c4;font-size:10px}}@media(max-width:900px){{.grid,.cols{{grid-template-columns:1fr 1fr}}}}@media(max-width:600px){{.grid,.cols{{grid-template-columns:1fr}}}}
</style></head><body><div class="wrap"><header><div class="tag">K4 NETWORK ARTIFACTS / PASSIVE INCIDENT INVESTIGATION</div><h1>Network Artifacts Investigation Report</h1><p>Engine { _e(generated) } · Verdict <b>{_e(result.get('verdict'))}</b> · Generated from uploaded evidence without executing uploaded payloads.</p></header>
<div class="grid"><div class="metric"><span>Risk score</span><strong class="{'high' if result.get('risk_score',0)>=70 else 'medium' if result.get('risk_score',0)>=40 else 'good'}">{_e(result.get('risk_score',0))}/100</strong></div><div class="metric"><span>Artifacts</span><strong>{_e(result.get('artifact_count',0))}</strong></div><div class="metric"><span>Events</span><strong>{_e(summary.get('events',0))}</strong></div><div class="metric"><span>Findings</span><strong>{_e(len(findings))}</strong></div></div>
<h2>1. Executive summary</h2><div class="panel"><p>{_e(result.get('narrative'))}</p><div class="pre">{_e(json.dumps(summary,indent=2,default=str))}</div></div>
<h2>2. Evidence inventory and hashes</h2>{_table([(a.get('artifact',{}).get('filename'),a.get('artifact',{}).get('artifact_type'),a.get('artifact',{}).get('size_bytes'),a.get('artifact',{}).get('sha256')) for a in artifacts],['Artifact','Type','Bytes','SHA-256'])}
<h3>File analysis</h3>{_table(file_rows,['File','Type','Size','MD5','SHA-1','SHA-256','Entropy'])}
<h2>3. Findings and behavioral detections</h2>{_table(finding_rows,['Finding','Severity','Confidence','Score','Reason'])}
<div class="cols"><div><h3>Beaconing / C2 candidates</h3>{_table([(x.get('source'),x.get('destination'),x.get('port'),x.get('observations'),x.get('mean_interval_seconds'),x.get('confidence')) for x in behavioral.get('beaconing_candidates',[])[:100]],['Source','Destination','Port','Obs.','Mean interval','Confidence'])}</div><div><h3>DNS tunneling / DGA candidates</h3>{_table([(x.get('domain'),x.get('entropy'),x.get('longest_label'),x.get('confidence')) for x in behavioral.get('dns_tunneling_candidates',[])[:100]],['Domain','Entropy','Longest label','Confidence'])}</div></div>
<h2>4. Attacker behaviour reconstruction</h2><div class="panel"><p>This section reconstructs observable network behaviour only. A source IP is not automatically an attacker identity, and a heuristic candidate is not proof of compromise.</p>{_table([(x.get('source_ip'),x.get('connections'),', '.join(x.get('internal_targets',[])),x.get('assessment')) for x in result.get('external_sources',[])[:200]],['External source','Connections','Internal targets','Assessment'])}</div>
<h2>5. Network relationship graph</h2>{_graph_svg(graph)}<p>Nodes and edges represent observed relationships. Public/private scope is derived from IP address classification.</p>
<h2>6. IOC explorer</h2>{_table(ioc_rows[:2000],['Type','Value'])}
<h2>7. MITRE ATT&CK candidate mapping</h2>{_table(mitre_rows,['Technique','Name','Tactic','Confidence','Evidence basis'])}
<h2>8. Unified timeline</h2>{_table(event_rows,['Timestamp','Source','Event','Source IP','Destination IP','Dst Port','Protocol','Message'])}
<h2>9. Incident-response workflow</h2>{phases}<h3>Evidence preservation</h3><div class="pre">{_e(json.dumps(ir.get('evidence_preservation',{}),indent=2))}</div><h3>Recommended follow-up collection</h3>{_table([(x.get('finding'),x.get('priority'),x.get('next_collection')) for x in ir.get('follow_up_evidence',[])],['Finding','Priority','Next collection'])}
<h2>10. Threat-intelligence status</h2>{_table([(k,v.get('status'),', '.join(v.get('providers',[])),v.get('reason')) for k,v in (result.get('threat_intel_ledger') or {}).items()],['IOC','Status','Providers','Reason'])}
<h2>11. Limitations and analyst notes</h2><div class="panel"><p>Passive network evidence can show communications, metadata, protocol observations and correlations. It cannot by itself prove user intent, compromise, attacker identity, or maliciousness. Encrypted application content is not decrypted. Live reputation providers are not represented as having returned results unless explicitly configured and integrated. File carving is bounded and best-effort.</p></div>
</div></body></html>'''
    return doc.encode('utf-8')
