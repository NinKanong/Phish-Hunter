# Attack Surface Normalization

This module turns DNSDumpster-style domain data into an analyst-friendly attack-surface model.

Primary table fields:

- Host
- IP
- ASN
- ASN Name
- Open Services / Banners
- PTR / Reverse DNS
- Country / Country Code
- ASN Range
- Reverse-IP neighbor hosts

Raw provider observations stay under `dnsdumpster`; normalized rows are under `url_domain_vnext.attack_surface`.

No host/service is invented when the provider did not return it.
