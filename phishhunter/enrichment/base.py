from dataclasses import dataclass
from typing import Any

@dataclass
class EnrichmentResult:
    provider: str
    indicator: str
    found: bool
    score: int|None
    raw: dict[str,Any]
