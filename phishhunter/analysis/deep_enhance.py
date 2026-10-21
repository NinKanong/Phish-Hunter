from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from collections import defaultdict
import re

from phishhunter.analysis.depth_contract import capability_manifest

UTC = timezone.utc


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _flatten_iocs(iocs: dict) -> list[dict]:
    out = []
    for kind, values in (iocs or {}).items():
        if not isinstance(values, list):
            continue
        for value in values:
            text = str(value).strip()
            if text:
                out.append({'type': str(kind), 'value': text})
    return out


def _evidence_id(value: object) -> str:
    return 'EV-' + sha256(str(value).encode('utf-8', 'replace')).hexdigest()[:12].upper()


def _severity(score: int) -> str:
    if score >= 90: return 'critical'
    if score >= 70: return 'high'
    if score >= 40: return 'medium'
    if score > 0: return 'low'
    return 'info'


def _signal_score(item: dict) -> int:
    for key in ('score', 'risk_score', 'suspicion'):
        try:
            if item.get(key) is not None:
                return max(0, min(100, int(float(item[key]))))
        except (TypeError, ValueError):
            pass
    sev = str(item.get('severity', '')).lower()
    return {'critical': 95, 'high': 75, 'medium': 50, 'low': 25, 'info': 0}.get(sev, 0)


def _raw_evidence(item: dict, source: str, index: int) -> dict:
    raw = item.get('raw_evidence') or item.get('raw') or item.get('detail') or item.get('value') or item
    return {
        'id': _evidence_id(f'{source}:{index}:{raw}'),
        'source': source,
        'kind': item.get('evidence_type', item.get('type', 'structured-observation')),
        'location': item.get('location') or item.get('offset') or item.get('field') or 'analysis-result',
        'raw': raw,
        'interpretation': item.get('interpretation') or item.get('reason') or item.get('detail') or 'Observed artifact retained as raw evidence for analyst review.',
        'observed_at': item.get('timestamp') or now_iso(),
    }


def _finding(item: dict, evidence: dict, index: int, service_key: str, iocs: list[dict]) -> dict:
    score = _signal_score(item)
    confidence = item.get('confidence')
    if isinstance(confidence, str):
        confidence = {'high': 90, 'medium': 65, 'low': 35, 'heuristic': 55, 'observed': 90}.get(confidence.lower(), 50)
    try: confidence = max(0, min(100, int(confidence)))
    except (TypeError, ValueError): confidence = 70 if evidence['kind'] != 'heuristic' else 55
    name = str(item.get('name') or item.get('signal') or item.get('type') or 'Observed analyst finding')
    related = []
    text = str(item)
    for ioc in iocs:
        if ioc['value'] in text or len(related) < 3:
            related.append(ioc)
        if len(related) >= 10:
            break
    technique = item.get('mitre') or item.get('mitre_technique')
    techniques = []
    if technique:
        if isinstance(technique, dict): techniques.append(technique)
        else: techniques.append({'id': str(technique), 'name': item.get('mitre_name', 'Technique observed'), 'evidence_id': evidence['id'], 'confidence': confidence})
    return {
        'id': f'K4-{service_key.upper().replace("-", "")[:8]}-{index:04d}',
        'name': name,
        'what_found': str(item.get('detail') or item.get('description') or item.get('value') or name),
        'raw_evidence_ids': [evidence['id']],
        'interpretation': evidence['interpretation'],
        'mitre_attack': techniques,
        'confidence': confidence,
        'severity': str(item.get('severity') or _severity(score)),
        'score': score,
        'threat_intel': item.get('threat_intel') or {'status': 'not_configured', 'reason': 'No live provider result was supplied for this finding.', 'looked_up_at': now_iso()},
        'first_seen': item.get('first_seen') or evidence['observed_at'],
        'last_seen': item.get('last_seen') or evidence['observed_at'],
        'related_iocs': related,
        'source': evidence['source'],
        'status': 'observed' if evidence['kind'] != 'heuristic' else 'candidate',
    }


def enhance_result(result: dict, service_key: str, target: str = '') -> dict:
    """Apply the universal depth contract without inventing external intelligence."""
    result = dict(result or {})
    ioc_list = _flatten_iocs(result.get('iocs') or {})
    raw_items = []
    for source_key in ('evidence', 'findings'):
        values = result.get(source_key) or []
        if isinstance(values, list):
            raw_items.extend((source_key, x) for x in values if isinstance(x, dict))
    for key in ('dns', 'flows', 'sample_packets'):
        values = result.get(key) or []
        if isinstance(values, list):
            # Keep the ledger bounded while retaining representative raw records.
            raw_items.extend((key, x) for x in values[:1000] if isinstance(x, dict))

    evidence = []
    findings = []
    seen = set()
    for idx, (source, item) in enumerate(raw_items, 1):
        ev = _raw_evidence(item, source, idx)
        evidence.append(ev)
        signature = (item.get('name'), item.get('signal'), item.get('type'), item.get('value'), item.get('detail'))
        if signature not in seen and (source in {'evidence', 'findings'} or _signal_score(item) > 0):
            seen.add(signature)
            findings.append(_finding(item, ev, len(findings) + 1, service_key, ioc_list))

    # Ensure each extracted IOC has a traceable evidence record.
    for idx, ioc in enumerate(ioc_list[:5000], len(evidence) + 1):
        ev = {
            'id': _evidence_id(f'ioc:{ioc}'), 'source': 'ioc-extraction', 'kind': 'ioc',
            'location': 'normalized-ioc-set', 'raw': ioc['value'],
            'interpretation': f"Observed {ioc['type']} indicator extracted from the submitted artifact.",
            'observed_at': now_iso(),
        }
        evidence.append(ev)
        if not any(f['related_iocs'] and f['related_iocs'][0]['value'] == ioc['value'] for f in findings):
            findings.append(_finding({'name': f'Observed {ioc["type"]} indicator', 'value': ioc['value'], 'confidence': 90}, ev, len(findings) + 1, service_key, [ioc]))

    timeline = []
    for ev in evidence:
        timeline.append({'timestamp': ev['observed_at'], 'event': ev['kind'], 'source': ev['source'], 'evidence_id': ev['id'], 'description': ev['interpretation']})
    timeline.sort(key=lambda x: x['timestamp'])

    intel = {}
    for ioc in ioc_list:
        intel_key = f"{ioc['type']}:{ioc['value']}"
        intel[intel_key] = {'ioc': ioc, 'status': 'not_configured', 'sources': [], 'queried_at': None, 'reason': 'No external provider credentials or connector execution result is available in this environment.'}

    # Technique observations must point to evidence. Existing mappings are preserved.
    mitre = []
    for item in result.get('mitre_techniques') or []:
        if not isinstance(item, dict):
            continue
        item = dict(item)
        item.setdefault('confidence', 70)
        item.setdefault('evidence_ids', [x['id'] for x in evidence[:1]])
        mitre.append(item)
    for finding in findings:
        for tech in finding['mitre_attack']:
            mitre.append(tech)

    score = int(result.get('risk_score', 0) or 0)
    signals = []
    for f in findings:
        if f['score'] > 0:
            signals.append({'finding_id': f['id'], 'name': f['name'], 'weight': f['score'], 'contribution': round(f['score'] / max(1, len(findings)), 2)})
    if not score and signals:
        score = min(100, max(s['weight'] for s in signals))

    result['depth_contract'] = capability_manifest(service_key)
    result['raw_evidence'] = evidence
    result['findings'] = findings
    result['timeline'] = timeline
    result['threat_intel_ledger'] = intel
    result['mitre_techniques'] = mitre
    result['risk_breakdown'] = {
        'score': score, 'verdict': result.get('verdict', 'unknown'), 'signals': signals[:200],
        'counter_signals': [], 'explanation': 'Risk is derived only from analyzer observations retained in the evidence ledger; external intelligence is not fabricated.'
    }
    result['report_metadata'] = {
        'service': service_key, 'target': target[:10000], 'generated_at': now_iso(),
        'chain_of_custody': {'intake_hash': sha256(str(target).encode()).hexdigest(), 'analysis_engine': result.get('analysis_engine', {})},
    }
    result['self_verification'] = verify_depth_contract(result)
    return result


def verify_depth_contract(result: dict) -> dict:
    checks = []
    findings = result.get('findings') or []
    evidence_ids = {x.get('id') for x in result.get('raw_evidence') or []}
    for f in findings:
        checks.append({'finding_id': f.get('id'), 'evidence_linked': all(e in evidence_ids for e in f.get('raw_evidence_ids', [])), 'confidence_valid': 0 <= int(f.get('confidence', -1)) <= 100})
    missing = [x for x in checks if not (x['evidence_linked'] and x['confidence_valid'])]
    return {
        'status': 'verified' if not missing else 'review_required',
        'finding_count': len(findings), 'evidence_count': len(result.get('raw_evidence') or []),
        'timeline_count': len(result.get('timeline') or []), 'ioc_count': len(_flatten_iocs(result.get('iocs') or {})),
        'checks': checks[:5000], 'issues': missing,
        'checked_at': now_iso(),
    }
