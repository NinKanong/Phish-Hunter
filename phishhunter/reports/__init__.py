"""Reports tool module with backward-compatible exports."""
from phishhunter.report_core import (
    report_html,
    report_json,
    report_markdown,
    report_stix,
    report_pdf,
    report_ioc_csv,
    report_connections_csv,
    report_text,
    report_bundle,
    report_export,
    available_report_formats,
    executive_summary,
)
from .manifest import manifest

__all__ = [
    "manifest", "report_html", "report_json", "report_markdown", "report_stix",
    "report_pdf", "report_ioc_csv", "report_connections_csv", "report_text",
    "report_bundle", "report_export", "available_report_formats", "executive_summary",
]
