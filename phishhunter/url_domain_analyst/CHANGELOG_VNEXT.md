# URL & Domain Analyst vNext

## 10.0
- Converted the module from a thin adapter into a capability-oriented rebuild boundary.
- Added typed evidence/entity/relationship models.
- Added URL 200-field contract, deep URL parsing, decoding, obfuscation and secret-pattern heuristics.
- Added domain anatomy and IDN/public-suffix boundary.
- Added 60+ DNS record contract, email authentication parsing and DNSSEC posture.
- Added RDAP lifecycle, CT aggregation, IP/ASN/hosting/CDN/WAF analysis, HTTP/TLS posture.
- Added reputation fusion and provider-scoped breach exposure.
- Added typed graph building, shortest-path/cluster support, ten-dimensional scoring and evidence ledger.
- Added 52 capability families with 778 internal capability slots.
- Added explicit connector status model and safe provider HTTP client boundary.
- Wired the web URL/domain service to the module engine while preserving stable result keys.

## Evidence discipline
External provider data is only treated as live when explicitly configured. Provider-dependent or historical fields remain marked as provider-dependent. No direct Tor/dark-web crawling is claimed.
