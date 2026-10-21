from __future__ import annotations
from dataclasses import dataclass,field
from typing import Any

@dataclass
class InvestigationMemory:
    facts:list[dict[str,Any]]=field(default_factory=list)
    questions:list[str]=field(default_factory=list)
    decisions:list[dict[str,Any]]=field(default_factory=list)
    def add_fact(self,kind:str,value:Any,evidence:Any=None): self.facts.append({'kind':kind,'value':value,'evidence':evidence})
    def add_question(self,q:str): self.questions.append(q)
    def decide(self,action:str,reason:str): self.decisions.append({'action':action,'reason':reason})
