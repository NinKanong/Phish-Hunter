from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any

@dataclass(frozen=True)
class AttackSurfaceRow:
    host: str
    ip: str
    asn: str = ""
    asn_name: str = ""
    asn_range: str = ""
    open_services: tuple[str, ...] = ()
    ptr: str = ""
    country: str = ""
    country_code: str = ""
    reverse_ip_neighbor_count: int = 0
    reverse_ip_neighbors: tuple[str, ...] = ()
    record_family: str = "A"
    source: str = "provider-returned"

    def to_dict(self) -> dict[str, Any]:
        d=asdict(self)
        d["open_services"]=list(self.open_services)
        d["reverse_ip_neighbors"]=list(self.reverse_ip_neighbors)
        return d

def from_row(row: Any) -> AttackSurfaceRow:
    row=row if isinstance(row,dict) else {}
    services=tuple(str(x) for x in (row.get("open_services") or []) if str(x).strip())
    neighbors=tuple(str(x) for x in (row.get("reverse_ip_neighbors") or []) if str(x).strip())
    try: count=int(row.get("reverse_ip_neighbor_count") or len(neighbors))
    except (TypeError,ValueError): count=len(neighbors)
    return AttackSurfaceRow(
        host=str(row.get("host") or ""), ip=str(row.get("ip") or ""), asn=str(row.get("asn") or ""),
        asn_name=str(row.get("asn_name") or ""), asn_range=str(row.get("asn_range") or ""),
        open_services=services, ptr=str(row.get("ptr") or ""), country=str(row.get("country") or ""),
        country_code=str(row.get("country_code") or ""), reverse_ip_neighbor_count=count,
        reverse_ip_neighbors=neighbors, record_family=str(row.get("record_family") or "A"),
        source=str(row.get("source") or "provider-returned"),
    )
