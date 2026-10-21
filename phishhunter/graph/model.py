from dataclasses import dataclass
@dataclass(frozen=True)
class Edge:
    source:str
    relation:str
    target:str
