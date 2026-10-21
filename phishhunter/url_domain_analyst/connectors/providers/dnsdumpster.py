from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

ENDPOINT = "https://api.dnsdumpster.com/domain/{domain}"
BANNER_ENDPOINT = "https://api.dnsdumpster.com/banners/{cidr}"
RATE_LIMIT_SECONDS = 2.0


def request_url(domain: str, page: int | None = None, include_map: bool = False) -> str:
    url = ENDPOINT.format(domain=quote(str(domain or "").strip(), safe=""))
    params: list[str] = []
    if page and page > 1:
        params.append(f"page={int(page)}")
    if include_map:
        params.append("map=1")
    return url + ("?" + "&".join(params) if params else "")


async def lookup(client: httpx.AsyncClient, domain: str, api_key: str, *, page: int | None = None, include_map: bool = False) -> dict[str, Any]:
    if not api_key:
        return {"status": "not_configured", "provider": "DNSDumpster", "records": {}}
    try:
        response = await client.get(
            request_url(domain, page=page, include_map=include_map),
            headers={"X-API-Key": api_key, "accept": "application/json"},
        )
        if response.status_code >= 400:
            return {
                "status": response.status_code,
                "provider": "DNSDumpster",
                "records": {},
                "error": response.text[:500],
                "request_url": request_url(domain, page=page, include_map=include_map),
            }
        payload = response.json()
        return {
            "status": "completed",
            "provider": "DNSDumpster",
            "records": payload if isinstance(payload, dict) else {},
            "request_url": request_url(domain, page=page, include_map=include_map),
        }
    except Exception as exc:
        return {"status": "error", "provider": "DNSDumpster", "records": {}, "error": str(exc)[:500]}


async def banner_lookup(client: httpx.AsyncClient, cidr: str, api_key: str) -> dict[str, Any]:
    if not api_key:
        return {"status": "not_configured", "provider": "DNSDumpster", "records": []}
    try:
        response = await client.get(
            BANNER_ENDPOINT.format(cidr=quote(str(cidr or "").strip(), safe="/")),
            headers={"X-API-Key": api_key, "accept": "application/json"},
        )
        if response.status_code >= 400:
            return {"status": response.status_code, "provider": "DNSDumpster", "records": [], "error": response.text[:500]}
        payload = response.json()
        return {"status": "completed", "provider": "DNSDumpster", "records": payload if isinstance(payload, (dict, list)) else []}
    except Exception as exc:
        return {"status": "error", "provider": "DNSDumpster", "records": [], "error": str(exc)[:500]}
