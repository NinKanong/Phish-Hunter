from __future__ import annotations

def report_manifest() -> dict:
    return {"formats": ["json", "markdown", "html", "csv", "stix", "pdf"], "chain_of_custody": True, "evidence_provenance": True}
