from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable


EMPTY_SURFACE = {
    "status": "provider-dependent",
    "source": "DNSDumpster",
    "a_records": [],
    "aaaa_records": [],
    "cname_records": [],
    "mx_records": [],
    "ns_records": [],
    "txt_records": [],
    "services": [],
    "countries": [],
    "hosting_networks": [],
    "ip_reuse": [],
    "subdomains": [],
    "current_resolver_ips": [],
    "summary": {},
    "table_columns": [],
    "source_policy": "provider-dependent",
}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _records(payload: Any, key: str) -> list[dict[str, Any]]:
    value = _as_dict(payload).get(key)
    return [row for row in _as_list(value) if isinstance(row, dict)]


def _ip_rows(row: dict[str, Any]) -> list[dict[str, Any]]:
    if _clean(row.get("value")) and not row.get("ips") and not row.get("ip"):
        return [{"ip": _clean(row.get("value")), "source": row.get("source")} ]
    raw = row.get("ips")
    if isinstance(raw, list):
        out: list[dict[str, Any]] = []
        for item in raw:
            if isinstance(item, dict):
                out.append(item)
            elif _clean(item):
                out.append({"ip": _clean(item)})
        return out
    single = row.get("ip")
    return [{"ip": _clean(single)}] if _clean(single) else []


def _banner_records(banners: Any, host: str, ip: str, source: str = "DNSDumpster") -> list[dict[str, Any]]:
    """Flatten DNSDumpster-style protocol banner payloads without inventing ports."""
    out: list[dict[str, Any]] = []
    if not isinstance(banners, dict):
        return out
    for protocol, payload in banners.items():
        protocol_name = _clean(protocol).lower()
        if not isinstance(payload, dict):
            if _clean(payload):
                out.append({
                    "host": host,
                    "ip": ip,
                    "protocol": protocol_name,
                    "port": None,
                    "port_inference": "none",
                    "service": _clean(payload),
                    "product": None,
                    "version": None,
                    "server": None,
                    "title": None,
                    "apps": [],
                    "alt_names": [],
                    "source": source,
                })
            continue
        apps = [_clean(x) for x in _as_list(payload.get("apps")) if _clean(x)]
        alt_names = [_clean(x) for x in _as_list(payload.get("alt_n")) if _clean(x)]
        # HTTP/HTTPS conventional ports are only a protocol-derived presentation aid.
        # The provider payload remains the authoritative observation.
        port = 80 if protocol_name == "http" else 443 if protocol_name == "https" else None
        port_inference = "protocol-default" if port else "none"
        service_name = _clean(payload.get("service") or payload.get("product") or payload.get("software")) or (apps[0] if apps else None)
        out.append({
            "host": host,
            "ip": ip,
            "protocol": protocol_name or None,
            "port": port,
            "port_inference": port_inference,
            "service": service_name,
            "product": _clean(payload.get("product") or payload.get("software")) or None,
            "version": _clean(payload.get("version")) or None,
            "server": _clean(payload.get("server")) or None,
            "title": _clean(payload.get("title")) or None,
            "apps": apps,
            "alt_names": alt_names,
            "common_name": _clean(payload.get("cn")) or None,
            "raw": payload,
            "source": "DNSDumpster",
        })
    return out


def _service_labels(banner_rows: Iterable[dict[str, Any]]) -> list[str]:
    labels: list[str] = []
    for banner in banner_rows:
        protocol = _clean(banner.get("protocol"))
        port = banner.get("port")
        for value in [banner.get("service"), banner.get("product"), banner.get("server"), banner.get("version")]:
            text = _clean(value)
            if text:
                suffix = f" ({protocol}:{port})" if protocol and port else f" ({protocol})" if protocol else ""
                labels.append(f"{text}{suffix}")
        for app in _as_list(banner.get("apps")):
            text = _clean(app)
            if text:
                suffix = f" ({protocol}:{port})" if protocol and port else f" ({protocol})" if protocol else ""
                labels.append(f"{text}{suffix}")
    return sorted(dict.fromkeys(labels))


def _provider_ip_intel(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in _as_list(result.get("ip_intelligence")):
        if isinstance(row, dict) and _clean(row.get("ip")):
            index[_clean(row.get("ip"))] = row
    return index


def _row_ip_intel(provider_ip: dict[str, Any], local: dict[str, Any]) -> dict[str, Any]:
    ptrs = local.get("ptr") if isinstance(local.get("ptr"), list) else []
    return {
        "asn": _clean(provider_ip.get("asn") or local.get("asn")),
        "asn_name": _clean(provider_ip.get("asn_name") or local.get("asn_name") or local.get("organization")),
        "asn_range": _clean(provider_ip.get("asn_range") or local.get("asn_range")),
        "ptr": _clean(provider_ip.get("ptr") or (ptrs[0] if ptrs else "")),
        "classification": _clean(local.get("classification")),
    }


def build(result: dict[str, Any]) -> dict[str, Any]:
    """Build a DNSDumpster-style attack-surface inventory from provider evidence.

    The function is deliberately passive: it never probes ports, synthesizes ASN data,
    or performs reverse-IP lookups. Reverse-IP values are labelled as dataset neighbors
    when multiple hosts in the returned provider dataset share an address.
    """
    result = _as_dict(result)
    raw = result.get("dnsdumpster")
    raw = raw if isinstance(raw, dict) else {}
    payload = _as_dict(raw.get("records"))
    # DNSDumpster is the preferred attack-surface source, but the product should not
    # become an empty shell when that API key is absent. Build a source-labelled fallback
    # from the already-collected passive DNS/DoH observations.
    resolver_dns = result.get("dns") if isinstance(result.get("dns"), dict) else {}
    resolver_records = resolver_dns.get("records") if isinstance(resolver_dns.get("records"), dict) else {}
    def resolver_rows(record_type: str) -> list[dict[str, Any]]:
        rows = resolver_records.get(record_type)
        if not isinstance(rows, list):
            return []
        out=[]
        for row in rows:
            if not isinstance(row, dict):
                continue
            value=_clean(row.get("value") or row.get("ip") or row.get("target") or row.get("exchange"))
            if not value:
                continue
            out.append({"host": _clean(row.get("name")) or _clean(result.get("domain")) or "unknown",
                        "value": value, "ttl": row.get("ttl"), "source": "DNS-over-HTTPS"})
        return out
    if not payload.get("a") and not payload.get("aaaa"):
        payload = {**payload,
                   "a": resolver_rows("A"),
                   "aaaa": resolver_rows("AAAA"),
                   "cname": resolver_rows("CNAME"),
                   "mx": resolver_rows("MX"),
                   "ns": resolver_rows("NS"),
                   "txt": resolver_rows("TXT")}
    rec = {key: _records(payload, key) for key in ("a", "aaaa", "cname", "mx", "ns", "txt")}
    ip_intel = _provider_ip_intel(result)

    hosts_by_ip: defaultdict[str, set[str]] = defaultdict(set)
    for record_family in ("a", "aaaa"):
        for row in rec[record_family]:
            host = _clean(row.get("host") or row.get("name"))
            if not host:
                continue
            for ip_row in _ip_rows(row):
                ip = _clean(ip_row.get("ip"))
                if ip:
                    hosts_by_ip[ip].add(host)

    a_records: list[dict[str, Any]] = []
    a_banner_rows: list[dict[str, Any]] = []
    all_hosts: set[str] = set()
    countries: Counter[str] = Counter()
    asn_names: Counter[str] = Counter()
    ip_counts: Counter[str] = Counter()

    for family in ("a", "aaaa"):
        for row in rec[family]:
            host = _clean(row.get("host") or row.get("name")) or "unknown"
            all_hosts.add(host)
            for provider_ip in _ip_rows(row):
                ip = _clean(provider_ip.get("ip"))
                if not ip:
                    continue
                local = ip_intel.get(ip, {})
                enrichment = _row_ip_intel(provider_ip, local)
                country = _clean(provider_ip.get("country") or local.get("country"))
                country_code = _clean(provider_ip.get("country_code") or local.get("country_code"))
                banner_rows = _banner_records(provider_ip.get("banners"), host, ip, _clean(provider_ip.get("source") or row.get("source") or raw.get("provider") or raw.get("source")) or ("DNSDumpster" if raw.get("status") == "completed" else "DNS-over-HTTPS"))
                a_banner_rows.extend(banner_rows)
                open_services = _service_labels(banner_rows)
                neighbor_hosts = sorted(x for x in hosts_by_ip.get(ip, set()) if x != host)
                if country:
                    countries[country] += 1
                asn = enrichment["asn"]
                asn_name = enrichment["asn_name"]
                if asn_name:
                    asn_names[asn_name] += 1
                ip_counts[ip] += 1
                row_source = _clean(provider_ip.get("source") or row.get("source") or raw.get("provider") or raw.get("source")) or ("DNSDumpster" if raw.get("status") == "completed" else "DNS-over-HTTPS")
                a_records.append({
                    "host": host,
                    "ip": ip,
                    "asn": asn,
                    "asn_name": asn_name,
                    "asn_range": enrichment["asn_range"],
                    "country": country,
                    "country_code": country_code,
                    "ptr": enrichment["ptr"],
                    "classification": enrichment["classification"],
                    "open_services": open_services,
                    "service_count": len(open_services),
                    "reverse_ip_neighbors": neighbor_hosts,
                    "reverse_ip_neighbor_count": len(neighbor_hosts),
                    "revip_status": "dataset-correlation" if neighbor_hosts else "no-neighbor-in-returned-dataset",
                    "banners": banner_rows,
                    "record_family": "A" if family == "a" else "AAAA",
                    "source": row_source,
                })

    def simple_records(key: str, fields: tuple[str, ...]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for row in rec[key]:
            normalized = {field: row.get(field) for field in fields if field in row}
            normalized["source"] = "DNSDumpster"
            rows.append(normalized)
        return rows

    cname_records = []
    for row in rec["cname"]:
        cname_records.append({
            "host": _clean(row.get("host") or row.get("name")),
            "target": _clean(row.get("value") or row.get("target") or row.get("cname")),
            "source": "DNSDumpster",
        })
    mx_records = []
    for row in rec["mx"]:
        mx_records.append({
            "host": _clean(row.get("host") or row.get("name")),
            "exchange": _clean(row.get("value") or row.get("target") or row.get("exchange")),
            "priority": row.get("priority"),
            "source": "DNSDumpster",
        })
    ns_records = []
    for row in rec["ns"]:
        ns_records.append({
            "host": _clean(row.get("host") or row.get("name")),
            "nameserver": _clean(row.get("value") or row.get("target") or row.get("nameserver")),
            "source": "DNSDumpster",
        })
    txt_records = []
    for row in rec["txt"]:
        value = row.get("value") if row.get("value") is not None else row.get("txt") if row.get("txt") is not None else row
        txt_records.append({"value": _clean(value), "source": "DNSDumpster"})

    # Deduplicate service rows while retaining detailed banner context.
    service_rows: list[dict[str, Any]] = []
    seen_services: set[tuple[Any, ...]] = set()
    for row in a_banner_rows:
        key = (row.get("host"), row.get("ip"), row.get("protocol"), row.get("port"), row.get("service"), row.get("product"), row.get("version"), row.get("server"), row.get("title"))
        if key in seen_services:
            continue
        seen_services.add(key)
        service_rows.append(row)

    current_ips = sorted({
        _clean(x) for x in _as_dict(result.get("network_associations")).get("current_ips", []) if _clean(x)
    })
    subdomains = sorted(all_hosts)
    summary = {
        "a_records": sum(1 for row in a_records if row.get("record_family") == "A"),
        "aaaa_records": sum(1 for row in a_records if row.get("record_family") == "AAAA"),
        "unique_hosts": len(subdomains),
        "unique_ips": len(ip_counts),
        "unique_asns": len(asn_names),
        "countries": len(countries),
        "services": len(service_rows),
        "subdomains": len(subdomains),
        "cname": len(cname_records),
        "mx": len(mx_records),
        "ns": len(ns_records),
        "txt": len(txt_records),
        "current_resolver_ips": len(current_ips),
        "total_provider_rows": len(a_records),
    }

    derived_source = "DNSDumpster" if raw.get("status") == "completed" and (a_records or cname_records or mx_records or ns_records or txt_records) else ("DNS-over-HTTPS" if a_records or cname_records or mx_records or ns_records or txt_records else "provider-dependent")
    return {
        "status": "complete" if a_records or cname_records or mx_records or ns_records or txt_records else "provider-dependent",
        "source": _clean(raw.get("source")) or derived_source,
        "queried_at": raw.get("queried_at"),
        "provider_metadata": {
            "endpoint": "https://api.dnsdumpster.com/domain/{domain}",
            "rate_limit_note": "DNSDumpster documents a rate limit of 1 domain request per 2 seconds.",
            "pagination_note": "Additional host pages are provider/account dependent.",
            "banner_endpoint": "https://api.dnsdumpster.com/banners/{cidr}",
        },
        "limits": {
            "provider_note": "Results depend on the configured DNSDumpster account/API quota.",
        },
        "summary": summary,
        "a_records": a_records[:10000],
        "aaaa_records": [r for r in a_records if r.get("record_family") == "AAAA"][:10000],
        "cname_records": cname_records[:2000],
        "mx_records": mx_records[:2000],
        "ns_records": ns_records[:2000],
        "txt_records": txt_records[:5000],
        "services": service_rows[:10000],
        "countries": [{"country": country, "count": count} for country, count in countries.most_common()],
        "hosting_networks": [{"name": name, "count": count} for name, count in asn_names.most_common(100)],
        "ip_reuse": [{"ip": ip, "host_count": count, "hosts": sorted(hosts_by_ip.get(ip, set()))[:100]} for ip, count in ip_counts.most_common(500)],
        "subdomains": subdomains[:10000],
        "current_resolver_ips": current_ips,
        "table_columns": [
            "host", "ip", "asn", "asn_name", "open_services", "reverse_ip_neighbors",
            "ptr", "country", "country_code", "asn_range", "record_family", "source",
        ],
        "source_policy": "Provider-returned rows retain provenance. DNSDumpster is preferred; when unavailable, A/AAAA and core DNS rows may be built from the already-collected DNS-over-HTTPS resolver evidence. RevIP is only dataset-correlation unless a separate reverse-IP provider is configured.",
        "coverage": {
            "dnsdumpster": "preferred provider attack-surface source",
            "resolver_fallback": "current DNS-over-HTTPS observations",
            "reverse_ip": "dataset-scoped host reuse unless external provider is configured",
            "open_services": "provider banner observations only; protocol-default ports are labelled as inferred"
        },
    }
