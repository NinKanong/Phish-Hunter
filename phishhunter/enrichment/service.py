from __future__ import annotations

from typing import Any

from phishhunter.config import settings
from phishhunter.enrichment.registry import available_connectors


async def enrich_result(result: dict[str, Any], scan_type: str) -> dict[str, Any]:
    """Optionally enrich an analysis with configured live providers.

    The application never fabricates provider results. When enrichment is disabled or
    no provider is configured, a deterministic status object is returned instead.
    """
    base: dict[str, Any] = {
        "enabled": bool(settings.enable_external_ti),
        "providers": [],
        "errors": [],
    }
    if not settings.enable_external_ti:
        base["status"] = "disabled"
        return base

    connectors = available_connectors()
    if not connectors:
        base["status"] = "no_credentials"
        return base

    targets: list[tuple[str, str]] = []
    if scan_type == "file":
        sha256 = str(result.get("hashes", {}).get("sha256", "")).strip()
        if sha256:
            targets.append(("hash", sha256))
    elif scan_type == "url":
        url = str(result.get("url", "")).strip()
        if url:
            targets.append(("url", url))
    elif scan_type == "email":
        for url in (result.get("iocs", {}).get("urls", []) or [])[:50]:
            if str(url).strip():
                targets.append(("url", str(url).strip()))
        for attachment in (result.get("deep_attachments", []) or [])[:50]:
            sha256 = str(attachment.get("sha256", "")).strip()
            if len(sha256) == 64:
                targets.append(("hash", sha256))

    for connector in connectors:
        try:
            for kind, indicator in targets:
                if kind == "hash" and hasattr(connector, "lookup_hash"):
                    enriched = await connector.lookup_hash(indicator)
                elif kind == "url" and hasattr(connector, "search_url"):
                    enriched = await connector.search_url(indicator)
                else:
                    continue
                base["providers"].append(
                    {
                        "provider": enriched.provider,
                        "indicator": enriched.indicator,
                        "found": enriched.found,
                        "score": enriched.score,
                        "raw": enriched.raw,
                    }
                )
        except Exception as exc:
            base["errors"].append({"provider": getattr(connector, "name", type(connector).__name__), "error": str(exc)})

    base["status"] = "completed" if base["providers"] or not base["errors"] else "partial_failure"
    return base
