from __future__ import annotations

def build(result):
    s=result.get('summary') or {}; findings=result.get('findings') or []
    parts=[]
    parts.append(f"The investigation processed {result.get('artifact_count',0)} network artifact(s) and {s.get('events',0)} normalized observations.")
    if result.get('artifact_types'): parts.append('Artifact families observed: '+', '.join(result['artifact_types'])+'.')
    if findings:
        top=sorted(findings,key=lambda x:int(x.get('score',0) or 0),reverse=True)[:5]
        parts.append('The strongest heuristic observations were: '+ '; '.join(str(x.get('name')) for x in top)+'.')
    else: parts.append('No behavioral finding crossed the configured heuristic thresholds.')
    if result.get('external_sources'): parts.append(f"External-source candidates: {len(result['external_sources'])}.")
    if result.get('extracted_files'): parts.append(f"The bounded passive carving stage produced {len(result['extracted_files'])} file candidate(s); file boundaries should be independently validated.")
    parts.append('This report distinguishes observed evidence from heuristic interpretation. It does not establish attacker identity, maliciousness, or compromise by itself.')
    return ' '.join(parts)
