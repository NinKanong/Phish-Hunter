from __future__ import annotations

AGENT_POLICY = {"module": 'Threat Intelligence', "mode": "evidence-grounded", "must_separate": ["observed", "correlated", "inferred", "requires-verification"], "must_not_claim": ["compromise", "attribution", "maliciousness", "dark-web access"]}

def agent_manifest() -> dict:
    return AGENT_POLICY | {"prompt_layers": ["scope", "evidence", "pivots", "risk", "IR", "reporting"]}
