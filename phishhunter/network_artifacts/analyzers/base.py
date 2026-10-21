from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

@dataclass(slots=True)
class AnalysisContext:
    job_id:str
    artifact_id:str
    filename:str
    artifact_type:str
    data:bytes
    options:dict[str,Any]

class BaseAnalyzer(ABC):
    name='base'; version='1.0'
    @abstractmethod
    def analyze(self, context:AnalysisContext)->dict[str,Any]: ...
