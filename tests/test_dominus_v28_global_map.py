from pathlib import Path


def test_global_map_is_map_only_and_has_live_feed_controls():
    p = Path("phishhunter/web/templates/url_domain_result.html").read_text(encoding="utf-8")
    start = p.index('<section class="uha-section" id="uha-geo">')
    end = p.index('<section class="uha-section" id="uha-hosting">', start)
    geo = p[start:end]
    assert "GLOBAL LIVE MAP" in geo
    assert "WORLD // REALTIME MAP" in geo
    assert "LIVE SIGNALS" not in geo
    assert "DOMAIN HEALTH / RECON" not in geo
    assert "ISOLATE ACROSS CASE" not in geo
    assert "Target domain" not in geo
    assert "uhaGlobalCanvas" in geo
    assert "uhaGlobalLayerMenu" in geo
    assert "Case infrastructure" not in geo
    assert "uhaGlobalFullscreen" in geo


def test_global_live_map_contract_exposes_live_feeds():
    from phishhunter.url_domain_analyst.geo.live_map_contract import build
    out = build({"map_points": [], "country_layers": []}, {"locations": []})
    assert out["mode"] == "dominus-global-live-map-v29"
    assert "earthquakes" in out["layers"]
    assert "flights" in out["layers"]
    assert "case-infrastructure" not in out["layers"]
    assert {x["id"] for x in out["live_feeds"]} == {"usgs-earthquakes", "opensky-aircraft"}
