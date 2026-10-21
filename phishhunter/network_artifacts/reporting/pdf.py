from __future__ import annotations
from .html import report_html

def report_pdf(result):
    try:
        from weasyprint import HTML
    except Exception as exc:
        raise RuntimeError('WeasyPrint is not installed; PDF export is unavailable in this runtime') from exc
    return HTML(string=report_html(result).decode('utf-8')).write_pdf()
