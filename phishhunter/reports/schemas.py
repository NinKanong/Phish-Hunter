from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass(slots=True)
class EvidenceRef:
    id: str
    source: str
    observed_at: str = ""
    confidence: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)

@dataclass(slots=True)
class AnalystCase:
    target: str
    scope: str = "single-target"
    evidence: list[EvidenceRef] = field(default_factory=list)
    pivots: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)
