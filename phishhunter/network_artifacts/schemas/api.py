from __future__ import annotations
from pydantic import BaseModel

class ReportRequest(BaseModel):
    format: str = 'json'
