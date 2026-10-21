from pathlib import Path
import io
import zipfile

def test_health_cards_are_clickable_and_have_module_pivots():
    p = Path("phishhunter/web/templates/url_domain_result.html").read_text(encoding="utf-8")
    start = p.index('<section class="uha-section" id="uha-health">')
    end = p.index('<section class="uha-section" id="uha-domain-info">', start)
    health = p[start:end]
    assert 'data-health-check' in health
    assert 'openHealthDetail' in p
    assert 'COPY JSON' in p
    from phishhunter.url_domain_analyst.recon.domain_health import build
    out = build({"domain":"example.com"})
    assert all('module' in c and 'pivots' in c for c in out['checks'])

def test_advanced_osint_has_direct_target_prepared_links():
    from phishhunter.url_domain_analyst.advanced_osint.direct_links import build_direct_links
    links = build_direct_links('example.com')
    assert len(links) >= 15
    all_links = [x for rows in links.values() for x in rows]
    assert len(all_links) >= 50
    assert any('example.com' in x['url'] for x in all_links)
    assert all('auto_search' in x and 'access' in x for x in all_links)

def test_xlsx_export_is_multi_sheet_and_openable():
    from phishhunter.report_office import xlsx
    payload = xlsx('Example report', {
        'domain':'example.com','risk_score':12,'verdict':'low-risk',
        'executive_summary':'Evidence-backed test report',
        'silent_ai':{'status':'active','coverage_percent':57},
        'findings':[{'id':'F1','name':'Sample','severity':'low','confidence':88,'what_found':'Observed','interpretation':'Review'}],
        'health':{'checks':[{'name':'DNS','status':'HIT','detail':'31 records','source':'resolver','confidence':'high','module':'dns','pivots':['Open DNS']}]},
        'iocs':{'domains':['example.com']},
        'evidence':[{'id':'EV1','type':'dns','source':'resolver','timestamp':'2026-10-08','asset_id':'example.com','sha256':'abc','scan_id':'S1'}],
        'timeline':[{'timestamp':'2026-10-08','type':'observed','asset_id':'example.com','description':'scan','source':'engine'}],
        'advanced_osint':{'categories':[{'id':'search_engine','name':'Search','observed_fields':2,'direct_link_count':5,'execution':'public-web'}]},
    })
    with zipfile.ZipFile(io.BytesIO(payload)) as z:
        names = set(z.namelist())
        assert 'xl/workbook.xml' in names
        sheets = [n for n in names if n.startswith('xl/worksheets/sheet') and n.endswith('.xml')]
        assert len(sheets) >= 7
        assert z.testzip() is None

def test_report_export_ui_includes_excel_html_pdf_and_bundle():
    p = Path("phishhunter/web/templates/url_domain_result.html").read_text(encoding="utf-8")
    assert "('pdf','PDF')" in p
    assert "('xlsx','Excel XLSX')" in p
    assert "('html','Interactive HTML')" in p
    assert "('bundle-zip','Full Export Bundle')" in p
    assert '/services/reports/export' in p

def test_silent_ai_is_embedded_and_standalone_ai_section_is_removed():
    p = Path("phishhunter/web/templates/url_domain_result.html").read_text(encoding="utf-8")
    assert 'Silent AI active' in p
    assert 'id="uha-ai"' not in p
    assert "AI Investigation" not in p
