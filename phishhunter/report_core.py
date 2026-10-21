from __future__ import annotations

from datetime import datetime, timezone
import html
import io
import json
import zipfile
from uuid import NAMESPACE_URL, uuid5
from phishhunter.report_exporters import export_report, bundle_all, EXPORT_FORMATS


def _json(value):
    return json.dumps(value, indent=2, sort_keys=True, default=str)


def _risk_label(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _counts(scan: dict) -> dict:
    iocs = scan.get("iocs") or {}
    return {
        "iocs": sum(len(v) for v in iocs.values() if isinstance(v, list)),
        "evidence": len(scan.get("evidence") or []),
        "findings": len(scan.get("findings") or []),
        "mitre": len(scan.get("mitre_techniques") or []),
        "flows": len(scan.get("flows") or []),
        "dns": len(scan.get("dns") or []),
    }


def executive_summary(scan: dict) -> str:
    score = int(scan.get("risk_score", 0) or 0)
    verdict = str(scan.get("verdict", "unknown"))
    counts = _counts(scan)
    parts = [f"The analysis returned a {verdict} verdict with a risk score of {score}/100 ({_risk_label(score)})."]
    if counts["iocs"]:
        parts.append(f"The engine identified {counts['iocs']} indicator values across the available IOC categories.")
    if counts["evidence"] or counts["findings"]:
        parts.append(f"The evidence set contains {counts['evidence']} structured evidence items and {counts['findings']} findings.")
    if counts["mitre"]:
        parts.append(f"{counts['mitre']} ATT&CK-oriented technique observations were mapped.")
    assessment = scan.get("network_assessment") or {}
    compromised = assessment.get("potential_compromised_hosts") or []
    c2 = assessment.get("potential_c2_candidates") or []
    if compromised:
        parts.append(f"Passive network heuristics produced {len(compromised)} potential compromised-host candidate(s); these are not proof of compromise.")
    if c2:
        parts.append(f"Passive network heuristics produced {len(c2)} potential C2 flow candidate(s) for validation.")
    return " ".join(parts)


def report_json(title: str, scan: dict) -> str:
    return json.dumps({"title": title, "generated_at": datetime.now(timezone.utc).isoformat(), "executive_summary": executive_summary(scan), "scan": scan}, indent=2, default=str)


def report_markdown(title: str, scan: dict) -> str:
    counts = _counts(scan)
    lines = [
        f"# {title}", "", f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Verdict: **{scan.get('verdict', 'unknown')}**", f"Risk score: **{scan.get('risk_score', 0)}/100**", "",
        "## Executive summary", executive_summary(scan), "",
        "## Analyst metrics",
        f"- IOCs: {counts['iocs']}", f"- Evidence: {counts['evidence']}", f"- Findings: {counts['findings']}",
        f"- ATT&CK observations: {counts['mitre']}", f"- Network flows: {counts['flows']}", f"- DNS observations: {counts['dns']}", "",
        "## IOCs", "```json", _json(scan.get("iocs", {})), "```", "",
        "## Evidence", "```json", _json(scan.get("evidence", [])), "```", "",
        "## Findings", "```json", _json(scan.get("findings", [])), "```", "",
        "## ATT&CK-oriented observations", "```json", _json(scan.get("mitre_techniques", [])), "```", "",
    ]
    if scan.get("network_assessment"):
        lines += ["## Network forensic assessment", "```json", _json(scan["network_assessment"]), "```", ""]
    if scan.get("flows"):
        lines += ["## Network flows", "```json", _json(scan["flows"]), "```", ""]
    if scan.get("dns"):
        lines += ["## DNS observations", "```json", _json(scan["dns"]), "```", ""]
    lines += ["## Enrichment", "```json", _json(scan.get("enrichment", {})), "```", "", "## Relationship graph", "```json", _json(scan.get("graph", {})), "```", "", "## Correlation / attribution guardrail", "```json", _json(scan.get("correlation", scan.get("attribution_guardrail", {}))), "```", ""]
    return "\n".join(lines)


def _section_html(title: str, value, open_by_default: bool = False) -> str:
    body = html.escape(_json(value))
    return f"<details class='section' {'open' if open_by_default else ''}><summary>{html.escape(title)}</summary><pre>{body}</pre></details>"


def report_html(title: str, scan: dict) -> str:
    score = int(scan.get("risk_score", 0) or 0)
    counts = _counts(scan)
    cards = "".join(f"<div class='metric'><b>{html.escape(str(v))}</b><span>{html.escape(k)}</span></div>" for k, v in [("Risk", f"{score}/100"), ("IOCs", counts["iocs"]), ("Evidence", counts["evidence"]), ("Findings", counts["findings"]), ("ATT&CK", counts["mitre"])])
    sections = [
        _section_html("IOCs", scan.get("iocs", {}), True),
        _section_html("Evidence", scan.get("evidence", []), True),
        _section_html("Findings", scan.get("findings", [])),
        _section_html("ATT&CK mapping", scan.get("mitre_techniques", [])),
        _section_html("Threat intelligence / enrichment", scan.get("enrichment", {})),
        _section_html("Relationship graph", scan.get("graph", {})),
    ]
    if scan.get("network_assessment"):
        sections.insert(2, _section_html("Network forensic assessment", scan["network_assessment"], True))
        sections.insert(3, _section_html("Network flows", scan.get("flows", [])))
        sections.insert(4, _section_html("DNS observations", scan.get("dns", [])))
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title>
<style>body{{margin:0;background:#030711;color:#dbeafe;font:14px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}}main{{max-width:1400px;margin:0 auto;padding:40px 24px}}header{{border:1px solid #1e293b;background:#07101f;border-radius:20px;padding:28px;margin-bottom:20px}}h1{{margin:0;font-size:34px}}h2{{margin:28px 0 10px}}.eyebrow{{color:#22d3ee;font-weight:900;letter-spacing:.18em;font-size:11px}}.summary{{color:#94a3b8;max-width:1000px}}.metrics{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:20px 0}}.metric{{border:1px solid #1e293b;background:#050b16;border-radius:14px;padding:16px}}.metric b{{display:block;font-size:25px}}.metric span{{color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:.12em}}.section{{border:1px solid #1e293b;background:#050b16;border-radius:14px;margin:10px 0;overflow:hidden}}summary{{cursor:pointer;padding:15px;font-weight:800}}pre{{margin:0;padding:18px;overflow:auto;max-height:700px;color:#a5b4fc;white-space:pre-wrap}}@media(max-width:800px){{.metrics{{grid-template-columns:repeat(2,1fr)}}}}</style></head><body><main><header><div class='eyebrow'>CYBER-PHISH-K4 ANALYST REPORT</div><h1>{html.escape(title)}</h1><p class='summary'>{html.escape(executive_summary(scan))}</p></header><div class='metrics'>{cards}</div>{''.join(sections)}</main></body></html>"""


def _stix_id(kind: str, key: str) -> str:
    return f"{kind}--{uuid5(NAMESPACE_URL, 'https://phishhunter.local/stix/' + kind + '/' + key)}"


def _stix_indicator(pattern: str, name: str, description: str, created: str) -> dict:
    return {"type": "indicator", "spec_version": "2.1", "id": _stix_id("indicator", pattern), "created": created, "modified": created, "name": name, "pattern_type": "stix", "pattern": pattern, "valid_from": created, "description": description}


def report_stix(title: str, scan: dict) -> str:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    objects = [{"type": "report", "spec_version": "2.1", "id": _stix_id("report", title), "created": now, "modified": now, "name": title, "report_types": ["threat-report"], "description": executive_summary(scan)}]
    iocs = scan.get("iocs", {})
    for value in iocs.get("ipv4", iocs.get("ips", [])):
        if "." in value: objects.append(_stix_indicator(f"[ipv4-addr:value = '{value}']", "IPv4 IOC", "Observed during analysis.", now))
    for value in iocs.get("domains", []): objects.append(_stix_indicator(f"[domain-name:value = '{value}']", "Domain IOC", "Observed during analysis.", now))
    for value in iocs.get("urls", []): objects.append(_stix_indicator(f"[url:value = '{value.replace(chr(39), chr(92)+chr(39))}']", "URL IOC", "Observed during analysis.", now))
    for value in iocs.get("hashes", []):
        if len(value) == 64: objects.append(_stix_indicator(f"[file:hashes.'SHA-256' = '{value}']", "SHA-256 IOC", "Observed during analysis.", now))
        elif len(value) == 40: objects.append(_stix_indicator(f"[file:hashes.'SHA-1' = '{value}']", "SHA-1 IOC", "Observed during analysis.", now))
        elif len(value) == 32: objects.append(_stix_indicator(f"[file:hashes.MD5 = '{value}']", "MD5 IOC", "Observed during analysis.", now))
    return json.dumps({"type": "bundle", "id": _stix_id("bundle", title), "objects": objects}, indent=2)


def report_ioc_csv(scan: dict) -> str:
    import csv
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["type", "value"])
    for kind, values in (scan.get("iocs") or {}).items():
        if isinstance(values, list):
            for value in values:
                writer.writerow([kind, value])
    return out.getvalue()


def report_connections_csv(scan: dict) -> str:
    import csv
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["src", "sport", "dst", "dport", "protocol", "packets", "bytes", "first_seen", "last_seen", "tls_sni", "http_hosts"])
    for f in scan.get("flows") or []:
        writer.writerow([f.get("src"), f.get("sport"), f.get("dst"), f.get("dport"), f.get("protocol"), f.get("packets"), f.get("bytes"), f.get("first_seen"), f.get("last_seen"), ";".join(f.get("tls_sni") or []), ";".join(f.get("http_hosts") or [])])
    return out.getvalue()


def report_text(title: str, scan: dict) -> str:
    return f"{title}\n{'=' * len(title)}\n\n{executive_summary(scan)}\n\nVerdict: {scan.get('verdict', 'unknown')}\nRisk: {scan.get('risk_score', 0)}/100\n\nKey evidence:\n" + "\n".join(f"- {x}" for x in (scan.get("evidence") or [])[:50])


def report_pdf(title: str, scan: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted, PageBreak
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=14 * mm, leftMargin=14 * mm, topMargin=14 * mm, bottomMargin=14 * mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="K4Small", parent=styles["BodyText"], fontSize=8, leading=11, textColor=colors.HexColor("#334155")))
    styles.add(ParagraphStyle(name="K4H", parent=styles["Heading2"], fontSize=14, leading=18, textColor=colors.HexColor("#0f172a"), spaceBefore=12))
    story = [Paragraph(html.escape(title), styles["Title"]), Paragraph(f"Generated {datetime.now(timezone.utc).isoformat()}", styles["K4Small"]), Spacer(1, 8), Paragraph("Executive summary", styles["K4H"]), Paragraph(html.escape(executive_summary(scan)), styles["BodyText"]), Spacer(1, 10)]
    counts = _counts(scan)
    data = [["Risk", f"{scan.get('risk_score', 0)}/100"], ["Verdict", str(scan.get('verdict', 'unknown'))], ["IOCs", str(counts['iocs'])], ["Evidence", str(counts['evidence'])], ["Findings", str(counts['findings'])], ["ATT&CK", str(counts['mitre'])]]
    table = Table(data, colWidths=[45 * mm, 120 * mm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("GRID", (0, 0), (-1, -1), .4, colors.HexColor("#cbd5e1")), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [table]
    for heading, value in [("IOCs", scan.get("iocs", {})), ("Evidence", scan.get("evidence", [])), ("Findings", scan.get("findings", [])), ("ATT&CK mapping", scan.get("mitre_techniques", [])), ("Network forensic assessment", scan.get("network_assessment")), ("Enrichment", scan.get("enrichment", {}))]:
        if value:
            story += [Paragraph(heading, styles["K4H"]), Preformatted(_json(value)[:45000], styles["K4Small"])]
    doc.build(story)
    return buffer.getvalue()


def report_bundle(title: str, scan: dict) -> bytes:
    return bundle_all(title, scan, report_pdf(title, scan))


def report_export(format_key: str, title: str, scan: dict) -> tuple[bytes, str, str]:
    """Export a normalized report using one of the deep report formats."""
    return export_report(format_key, title, scan)


def available_report_formats() -> list[dict]:
    return [
        {"key": key, "label": label, "media_type": media, "extension": ext}
        for key, label, media, ext in EXPORT_FORMATS
    ]
