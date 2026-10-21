from pathlib import Path


def test_result_template_has_global_map_and_deep_domain_matrix():
    p = Path('phishhunter/web/templates/url_domain_result.html').read_text(encoding='utf-8')
    assert "'/static/url_domain/world.svg'" in p
    assert 'Deep Domain Field Explorer' in p
    assert 'data-domain-field-search' in p
    assert 'function initGlobalLiveMap' in p
    assert 'GLOBAL LIVE MAP' in p
    assert 'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson' in p
    assert 'https://opensky-network.org/api/states/all' in p
    assert 'Interactive world geometry could not be loaded' not in p


def test_domain_field_matrix_has_500_plus_fields():
    from phishhunter.url_domain_analyst.deep_intelligence.domain_field_matrix import build
    fields = build({'domain': 'example.com'}, {'ldh_name': 'example.com'})
    assert len(fields) >= 500
    assert all('ai' in f and 'status' in f and 'source' in f for f in fields)
