from __future__ import annotations
from typing import Any
from collections import Counter

SIZE_RANGES = {
    "SIZE_1":"1 employee", "SIZE_2":"2-10 employees", "SIZE_3":"11-50 employees", "SIZE_4":"51-200 employees",
    "SIZE_5":"201-500 employees", "SIZE_6":"501-1000 employees", "SIZE_7":"1001-5000 employees",
    "SIZE_8":"5001-10000 employees", "SIZE_9":"10001+ employees",
}


def _rows_from_wapp(w: dict[str, Any]) -> list[dict[str, Any]]:
    out=[]
    for idx, item in enumerate(w.get("employees") or []):
        if not isinstance(item,dict):
            continue
        name = str(item.get("name") or "").strip()
        title = str(item.get("title") or item.get("role") or "").strip()
        if not (name or title):
            continue
        out.append({"name":name or None,"title":title or None,"source":"Wappalyzer","confidence":75,"record":idx+1})
    return out[:5000]


def _rows_from_linkedin(li: dict[str, Any]) -> list[dict[str, Any]]:
    out=[]
    for item in li.get("people") or []:
        if not isinstance(item,dict):
            continue
        out.append({
            "name":" ".join(x for x in [item.get("firstName"),item.get("lastName")] if x).strip() or None,
            "title":item.get("headline"),"member":item.get("member"),
            "source":"LinkedIn official API","confidence":95,
        })
    return out[:200]


def build(*, wappalyzer: dict[str, Any] | None = None, linkedin: dict[str, Any] | None = None, domain: str = "") -> dict[str, Any]:
    w=wappalyzer if isinstance(wappalyzer,dict) else {}
    li=linkedin if isinstance(linkedin,dict) else {}
    company=w.get("company") if isinstance(w.get("company"),dict) else {}
    rows=_rows_from_wapp(w)+_rows_from_linkedin(li)
    seen=set(); dedup=[]
    for row in rows:
        key=(row.get("name"),row.get("title"),row.get("source"))
        if key not in seen:
            seen.add(key); dedup.append(row)
    size=company.get("company_size")
    size_label=SIZE_RANGES.get(str(size), size)
    return {
        "status":"complete" if (size_label or dedup or company.get("name")) else "provider-dependent",
        "domain":domain,"company_name":company.get("name") or company.get("inferred_name"),
        "industry":company.get("industry"),"company_type":company.get("company_type"),
        "founded":company.get("company_founded"),"locations":company.get("locations") or [],
        "linkedin_urls":company.get("linkedin") or [],
        "employee_size_range":size_label,
        "employee_exact_count": w.get("employee_count"),
        "employee_rows":dedup,
        "employee_observation_count":len(dedup),
        "estimated_count_method":"Provider-reported range only unless a provider returns an exact numeric employee count.",
        "privacy_boundary":"No LinkedIn page scraping. Personal rows are included only when returned by an authorized provider/API or supplied by the analyst.",
        "verification":"Employee rows are public-provider observations, not proof of current employment or employment relationship.",
    }
