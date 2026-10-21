from __future__ import annotations
from .ai.agent import evidence_grounded_prompt, task_plan
AGENT_POLICY={'module':'URL & Domain Analyst','mode':'evidence-grounded','must_separate':['observed','correlated','inferred','requires-verification'],
'must_not_claim':['compromise','attribution','ownership without evidence','dark-web access','fabricated breach evidence']}
def agent_manifest()->dict: return {**AGENT_POLICY,'prompt':evidence_grounded_prompt({}),'task_planner':'evidence-grounded deterministic plan'}
def plan(result:dict)->list[dict]: return task_plan(result)
