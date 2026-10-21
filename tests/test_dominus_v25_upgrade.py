from pathlib import Path


def test_advanced_osint_contracts_match_blueprint_counts():
    from phishhunter.url_domain_analyst.advanced_osint.catalog import CATEGORIES, build_source_catalog
    from phishhunter.url_domain_analyst.advanced_osint.fields import field_catalog
    from phishhunter.url_domain_analyst.advanced_osint.engine import build_advanced_osint
    assert len(CATEGORIES) == 15
    assert len(field_catalog()) == 545
    assert len(build_source_catalog(360)) >= 360
    out = build_advanced_osint({'domain':'example.com','url':'https://example.com'}, 'example.com')
    assert out['category_count'] == 15
    assert out['field_count'] == 545
    assert out['source_stats']['total'] >= 360
    assert out['pivot_count'] >= 45
    assert all('ai' in x and 'provenance' in x and 'status' in x for x in out['fields'])


def test_real_world_globe_contract_and_ui():
    p = Path('phishhunter/web/templates/url_domain_result.html').read_text(encoding='utf-8')
    assert 'GLOBAL LIVE MAP' in p
    assert 'WORLD // REALTIME MAP' in p
    assert '3D Globe' in p
    assert '2D World' in p
    assert 'LIVE SIGNALS' not in p
    assert 'DOMAIN HEALTH / RECON' not in p[p.index('<section class="uha-section" id="uha-geo">'):p.index('<section class="uha-section" id="uha-hosting">')]
    assert '/static/url_domain/world.svg' in p


def test_live_map_contract_declares_real_world_projection():
    from phishhunter.url_domain_analyst.geo.live_map_contract import build
    out = build({'map_points': [], 'country_layers': []}, {'locations': []})
    assert out['projection'] == 'equirectangular-2d + orthographic-3d globe texture'
    assert out['country_count'] >= 200
    assert 'drag-rotate' in out['controls']
