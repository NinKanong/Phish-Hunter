from phishhunter.report_core import (
    report_json, report_markdown, report_html, report_stix, report_pdf,
    report_ioc_csv, report_connections_csv, report_text, report_bundle,
)

_REPORTERS = {
    "json": report_json,
    "markdown": report_markdown,
    "html": report_html,
    "stix": report_stix,
    "pdf": report_pdf,
    "ioc-csv": report_ioc_csv,
    "connections-csv": report_connections_csv,
    "text": report_text,
    "bundle-zip": report_bundle,
}

def report(title: str, scan: dict, fmt: str = "json", **kwargs):
    reporter = _REPORTERS.get(fmt)
    if reporter is None:
        raise ValueError(f"Unsupported report format: {fmt}")
    return reporter(title, scan, **kwargs) if fmt not in {"ioc-csv", "connections-csv"} else reporter(scan)
