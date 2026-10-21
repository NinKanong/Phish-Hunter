from __future__ import annotations
from typing import Any

PHASES=[
 ('1. Preparation','Preserve originals, record hashes, establish case scope, and confirm authorized evidence sources.'),
 ('2. Detection & Triage','Identify artifact types, parse observations, prioritize anomalies, and establish initial severity.'),
 ('3. Containment Planning','Identify candidate affected assets and communication paths. Do not take containment actions automatically.'),
 ('4. Evidence Collection','Preserve packet/log evidence, extracted file hashes, IOC context, and timestamps with chain-of-custody references.'),
 ('5. Analysis','Pivot through hosts, flows, DNS, HTTP, TLS, files, alerts, and cross-artifact correlations.'),
 ('6. Eradication Planning','Translate supported findings into remediation hypotheses; verify with endpoint/security telemetry before action.'),
 ('7. Recovery Planning','Define validation checks for affected assets and monitor for recurrence after authorized remediation.'),
 ('8. Lessons Learned','Record gaps, false-positive candidates, missing telemetry, and follow-up collection requirements.'),
]

def build_incident_response(result:dict[str,Any])->dict[str,Any]:
    findings=result.get('findings') or []
    affected=sorted({x.get('source_ip') for x in result.get('external_sources',[]) if x.get('source_ip')} | {x.get('host') for x in result.get('network_assessment',{}).get('potential_compromised_hosts',[]) if x.get('host')})
    evidence_actions=[]
    for f in findings[:50]:
        evidence_actions.append({'finding':f.get('name'),'next_collection':'Correlate the cited flow/time with endpoint, authentication, DNS and EDR telemetry.','priority':'high' if f.get('severity')=='high' else 'medium'})
    return {
      'methodology':'NIST-style incident response lifecycle adapted for passive network evidence',
      'phases':[{'phase':name,'purpose':purpose,'status':'analysis_output' if i<6 else 'recommended_follow_up'} for i,(name,purpose) in enumerate(PHASES)],
      'affected_asset_candidates':affected[:200],
      'containment_candidates':[{'asset':x,'action':'Validate and, if independently confirmed compromised, follow organizational containment procedure.'} for x in affected[:100]],
      'evidence_preservation':{'original_artifacts_hashed':True,'hashes_per_artifact':['MD5','SHA-1','SHA-256','SHA-512'],'execution_of_uploaded_payloads':False},
      'follow_up_evidence':evidence_actions,
      'closure_criteria':['Correlate candidate findings with independent telemetry','Validate extracted-file boundaries and hashes','Document false positives and unresolved questions','Preserve report and source-artifact hashes'],
    }
