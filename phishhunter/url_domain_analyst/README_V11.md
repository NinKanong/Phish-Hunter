# URL & Domain Analyst v11

## Deep investigation additions

- Provider-backed system-location aggregation and local world map visualization.
- Hosting/network aggregation and service/banner normalization.
- 27-stage long-form orchestration registry.
- Historical DNS summary boundary.
- Certificate reuse analysis.
- ASN/cloud attribution heuristics with source labeling.
- Deep OSINT pivot generation.
- Breach/exposure provider matrix.
- Risk calibration with uncertainty interval.
- Evidence-grounded AI reasoning with observed/unknown/hypothesis separation.

## UI

The intake view explicitly communicates deep mode and exposes the staged pipeline. Result views isolate modules: System Locations / Hosting and Services / Banners are separate investigator views.

## Safety

The local web service is passive-first. It does not fabricate dark-web access or run arbitrary commands from the target input. Provider-returned geographic coordinates are plotted only when numeric coordinates are actually present.
