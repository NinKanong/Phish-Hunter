from __future__ import annotations
from dataclasses import dataclass,field
from typing import Any,Callable
from .memory import InvestigationMemory

@dataclass
class NetworkArtifactAgentController:
    job_id:str
    progress:Callable[[int,str],None]
    memory:InvestigationMemory=field(default_factory=InvestigationMemory)
    stages:list[dict[str,Any]]=field(default_factory=list)
    def plan(self):
        return [{'stage':x,'status':'planned'} for x in ['triage','artifact_parsing','deep_protocol_analysis','file_carving','correlation','behavioral_detection','identity_profiling','threat_intel','mitre_mapping','incident_response','timeline','graph','report']] 
    def step(self,name,percent,message,evidence=None):
        self.stages.append({'stage':name,'status':'completed','percent':percent,'message':message,'evidence_count':len(evidence) if isinstance(evidence,(list,dict)) else None})
        self.progress(percent,message)
    def investigate(self,result):
        # Deterministic controller boundary. A future LangGraph/Temporal adapter can replace nodes without changing evidence contracts.
        self.memory.add_fact('artifact_count',result.get('artifact_count'))
        self.memory.add_fact('finding_count',len(result.get('findings',[])))
        self.memory.add_question('Validate high-confidence candidates against endpoint/identity telemetry.')
        self.memory.decide('classify_disposition','Evidence-driven heuristic aggregation; no unsupported attribution.')
        return {'memory':{'facts':self.memory.facts,'questions':self.memory.questions,'decisions':self.memory.decisions},'stages':self.stages}
