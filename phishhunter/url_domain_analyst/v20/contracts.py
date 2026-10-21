from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass(slots=True)
class InvestigationEvent:
    event: str
    percent: int
    stage: str
    detail: str = ""
    state: str = "running"
    meta: dict[str, Any] = field(default_factory=dict)

@dataclass(slots=True)
class ProviderState:
    name: str
    status: str
    source: str = ""
    reason: str = ""
    observations: int = 0

@dataclass(slots=True)
class InvestigationContract:
    target: str
    profile: str = "deep"
    passive_first: bool = True
    provider_provenance_required: bool = True
    no_dynamic_javascript: bool = True
    no_arbitrary_command_execution: bool = True
