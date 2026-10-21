from __future__ import annotations
from typing import Any

STATES = {"live-configured", "public-observation", "provider-dependent", "catalog-only", "not-observed", "degraded"}

def summarize(provider_results: dict[str, Any] | None) -> dict[str, Any]:
    rows = []
    for name, value in (provider_results or {}).items():
        value = value if isinstance(value, dict) else {"value": value}
        status = str(value.get("status") or "not-observed")
        if status not in STATES:
            status = "degraded" if status in {"error", "timeout"} else "not-observed"
        rows.append({"provider": str(name), "status": status, "source": value.get("source") or value.get("url") or "", "observations": len(value.get("records") or []) if isinstance(value.get("records"), list) else 0})
    return {"count": len(rows), "rows": rows}
