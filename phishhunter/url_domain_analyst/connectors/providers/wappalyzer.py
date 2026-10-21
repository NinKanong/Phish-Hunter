from __future__ import annotations
from typing import Any
import httpx

ENDPOINT = "https://api.wappalyzer.com/v2/lookup/"

async def lookup(client: httpx.AsyncClient, url: str, api_key: str) -> dict[str, Any]:
    if not api_key:
        return {"status":"not_configured","provider":"Wappalyzer","technologies":[],"employees":[]}
    try:
        response = await client.get(
            ENDPOINT,
            params={"urls": url, "sets": "all", "recursive": "false"},
            headers={"x-api-key": api_key, "accept": "application/json"},
        )
        if response.status_code >= 400:
            return {"status":response.status_code,"provider":"Wappalyzer","technologies":[],"employees":[],"error":response.text[:500]}
        payload = response.json()
        row = payload[0] if isinstance(payload, list) and payload else payload
        if not isinstance(row, dict):
            return {"status":"invalid_payload","provider":"Wappalyzer","technologies":[],"employees":[]}
        technologies = [x for x in (row.get("technologies") or []) if isinstance(x, dict)]
        employee_raw=row.get("employees")
        employees = [x for x in (employee_raw or []) if isinstance(x, dict)] if isinstance(employee_raw, list) else []
        employee_count = employee_raw if isinstance(employee_raw, (int,float)) else row.get("employeeCount") if isinstance(row.get("employeeCount"),(int,float)) else None
        return {
            "status":"completed","provider":"Wappalyzer","url":url,
            "technologies":technologies[:1000],"employees":employees[:5000],"employee_count":employee_count,
            "company":{
                "name":row.get("companyName"),"inferred_name":row.get("inferredCompanyName"),
                "industry":row.get("industry"),"about":row.get("about"),
                "company_size":row.get("companySize"),"company_type":row.get("companyType"),
                "company_founded":row.get("companyFounded"),"locations":row.get("locations") or [],
                "linkedin":row.get("linkedin") or [],"social":{k:row.get(k) for k in ("x","facebook") if row.get(k)},
            },
            "contact":{k:row.get(k) or [] for k in ("email","verifiedEmail","safeEmail","phone")},
            "ip_country":row.get("ipCountry"),"ip_region":row.get("ipRegion"),"language":row.get("language"),
            "dns":{k:row.get(k) for k in ("dns.spf","dns.dmarc") if row.get(k) is not None},
        }
    except Exception as exc:
        return {"status":"error","provider":"Wappalyzer","technologies":[],"employees":[],"error":str(exc)}
