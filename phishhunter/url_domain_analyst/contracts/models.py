from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
import hashlib, json
from .enums import EvidenceKind

@dataclass(slots=True)
class Evidence:
    evidence_id: str
    source: str
    kind: EvidenceKind = EvidenceKind.OBSERVED
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence: float = 0.0
    title: str = ''
    locator: str = ''
    value: Any = None
    notes: str = ''

@dataclass(slots=True)
class Entity:
    entity_id: str
    kind: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)

@dataclass(slots=True)
class Relationship:
    relationship_id: str
    source_id: str
    target_id: str
    kind: str
    confidence: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)

@dataclass(slots=True)
class InvestigationPackage:
    target: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    entities: list[Entity] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    pivots: list[dict[str, Any]] = field(default_factory=list)
    risk: dict[str, Any] = field(default_factory=dict)

    def stable_payload(self) -> dict[str, Any]:
        return {
            'target': self.target, 'created_at': self.created_at,
            'entities': [asdict(x) for x in self.entities],
            'relationships': [asdict(x) for x in self.relationships],
            'evidence': [asdict(x) for x in self.evidence],
            'findings': self.findings, 'pivots': self.pivots, 'risk': self.risk,
        }

    def sha256(self) -> str:
        raw = json.dumps(self.stable_payload(), sort_keys=True, default=str, separators=(',', ':')).encode()
        return hashlib.sha256(raw).hexdigest()
