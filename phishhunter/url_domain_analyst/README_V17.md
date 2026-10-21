# URL & Domain Analyst V17

The V17 analyst is organized around a provider-backed attack-surface investigation.

## Core result surfaces
- A / AAAA host inventory with Host, IP, ASN, ASN Name, Open Services, RevIP, PTR, Country, Netblock and Source.
- System Locations with provider coordinates or explicitly-labelled country-level visualization.
- Hosting / Networks with ASN, organization, netblock and infrastructure reuse.
- Services / Banners with protocol, port, product, version, server, title and provenance.
- DNS, RDAP, CT, TLS, HTTP, content, reputation, breach provider state, OSINT, graph, scoring and evidence modules.

## Attack-surface source policy
DNSDumpster is the preferred provider for DNSDumpster-style records. If it is not configured, current DNS-over-HTTPS records already collected by the core analyzer can populate the same normalized A/AAAA schema. This fallback is labelled `DNS-over-HTTPS` and is not presented as a global Internet dataset.

## Safety / evidence policy
Reverse-IP is dataset correlation unless a dedicated reverse-IP provider is configured. Private corporate technologies, employee lists, and breach/dark-web claims are not fabricated.
