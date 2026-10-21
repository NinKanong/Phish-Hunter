# URL & Domain Analyst V17 — Deep Attack Surface

## Purpose
A single URL/domain investigation surface that starts with a required target and expands evidence in bounded stages.

## Primary attack-surface table
A/AAAA rows expose:

`Host | IP | ASN | ASN Name | Open Services (from DB/provider) | RevIP | PTR | Country | Country Code | Netblock | Record Family | Source`

The preferred provider is DNSDumpster. When it is not configured, current DNS-over-HTTPS A/AAAA observations collected by the core analyzer can populate the same schema and are labelled `DNS-over-HTTPS`.

## System Locations
The Earth view supports exact provider coordinates when returned. Country-only observations may be rendered using clearly-labelled country-centroid points. The UI never represents a centroid as an exact host location.

## Isolation
Every attack-surface row can be selected to open an isolated entity view. A row also has an API entity endpoint for future client-side pivots.

## Services / Banners
Service observations are normalized from provider banners and public HTTP metadata. Product, version, server, title, protocol and inferred/default ports are separated so inferred values are not confused with provider evidence.

## Provenance
Every observation keeps a source/provider label. Dataset-scoped RevIP is only host reuse inside the returned dataset unless a dedicated reverse-IP provider is configured.

## Safety
No arbitrary shell execution, private-system discovery, credential collection, LinkedIn access-control bypass, or fabricated breach/dark-web results are implemented.
