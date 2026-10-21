# DOMINUS ULTIMATE V25 — Deep OSINT + Real-World Globe Upgrade

## What changed

### Advanced OSINT
- 15 categories from the supplied blueprint.
- 545 field definitions (the supplied per-category counts sum to 545).
- 360 source/provider/adapter contracts.
- 45 priority pivot actions across 15 pivot chains.
- Field-level provenance, status and silent-AI state.
- Missing data is `not-observed`; no synthetic findings are generated.

### Live Global Map
- Replaced the synthetic blue-grid globe with a local, real-world geography texture derived from the bundled world geometry.
- Orthographic globe projection with drag rotation and wheel zoom.
- 2D equirectangular world view remains available.
- Country, network and corporate evidence markers.
- Evidence arcs are rendered only between independently observed geographic endpoints; they are explicitly not presented as physical network routes.
- Country/network/corporate click opens an evidence dossier and an `ISOLATE ACROSS CASE` action.
- Geographic isolation filters case-table evidence by the selected country/coordinate context and can be cleared.
- No remote map tiles or CDN are required for the base map.

### Domain Information
- Existing 520-field deep domain matrix retained.
- Advanced OSINT is now a separate 545-field evidence explorer instead of a shallow empty panel.

## Validation
- Python compileall: passed.
- Full pytest suite on a clean temporary SQLite database: passed (`79 passed`).
- Focused URL/domain regression + DOMINUS tests: passed (`26 passed`).
- Local Uvicorn server: workspace HTTP 200; bundled world geometry HTTP 200.
- Real local scan test: `tryhackme.com`, quick profile, completed and result HTTP 200.
- Result contained 545 OSINT rows, 520 domain matrix rows, 15 OSINT categories, 360 source contracts and 45 pivots.
- Browser JavaScript syntax check on the rendered result: passed.
- ZIP integrity: must be verified with `unzip -t` before delivery.

## Provider limitation
The build environment has no reliable outbound DNS/network access. Provider-dependent intelligence is therefore not fabricated. When deployed with authorized provider credentials and network access, the connector layer can populate the same schemas with real evidence.
