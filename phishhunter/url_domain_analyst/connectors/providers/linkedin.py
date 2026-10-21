from __future__ import annotations
from typing import Any
import httpx

BASE = "https://api.linkedin.com/rest"

async def organization_lookup(client: httpx.AsyncClient, organization_id: str, access_token: str, version: str) -> dict[str, Any]:
    if not access_token or not organization_id:
        return {"status":"not_configured","provider":"LinkedIn","organization":None,"people":[]}
    try:
        r = await client.get(
            f"{BASE}/organizations/{organization_id}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "X-Restli-Protocol-Version": "2.0.0",
                "Linkedin-Version": version,
                "Accept": "application/json",
            },
            timeout=20,
        )
        if r.status_code >= 400:
            return {"status":r.status_code,"provider":"LinkedIn","organization":None,"people":[],"error":r.text[:400]}
        data=r.json()
        return {
            "status":"completed","provider":"LinkedIn","organization":data,
            "people":[],
            "note":"Official API only; this adapter never scrapes linkedin.com pages or bypasses access controls.",
        }
    except Exception as exc:
        return {"status":"error","provider":"LinkedIn","organization":None,"people":[],"error":str(exc)}

async def people_typeahead(client: httpx.AsyncClient, organization_urn: str, keyword: str, access_token: str, version: str) -> dict[str, Any]:
    if not (access_token and organization_urn and keyword.strip()):
        return {"status":"not_configured","provider":"LinkedIn","people":[]}
    try:
        r = await client.get(
            f"{BASE}/peopleTypeahead",
            params={"q":"organizationFollowers","keywords":keyword,"organization":organization_urn},
            headers={
                "Authorization": f"Bearer {access_token}",
                "X-Restli-Protocol-Version": "2.0.0",
                "Linkedin-Version": version,
                "Accept": "application/json",
            },
            timeout=20,
        )
        if r.status_code >= 400:
            return {"status":r.status_code,"provider":"LinkedIn","people":[],"error":r.text[:400]}
        data=r.json()
        people=[]
        for item in (data.get("elements") if isinstance(data,dict) else []) or []:
            if not isinstance(item,dict):
                continue
            people.append({k:item.get(k) for k in ("member","firstName","lastName","headline") if item.get(k) is not None})
        return {
            "status":"completed","provider":"LinkedIn","people":people[:200],
            "paging":(data.get("paging") if isinstance(data,dict) else {}) or {},
            "note":"Official People Typeahead only; returned fields follow member privacy settings.",
        }
    except Exception as exc:
        return {"status":"error","provider":"LinkedIn","people":[],"error":str(exc)}
