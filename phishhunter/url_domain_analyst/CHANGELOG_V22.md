# V22 Global Domain Intelligence

## Major upgrades

- Detailed Domain Information panel with:
  - Domain
  - Registered On
  - Expires On
  - Updated On
  - Status
  - Name Servers
- Registrar information:
  - Registrar
  - IANA ID / registry public identifier when supplied
  - Abuse Email / Phone when supplied
  - Registrar handle
- Registrant contact normalization:
  - Name
  - Organization
  - Street
  - City
  - State / Region
  - Postal Code
  - Country / country code
  - Phone
  - Email
- Detailed current DNS Lookup Matrix for A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, NAPTR, DNSKEY, DS, RRSIG, TLSA and SSHFP.
- Interactive world map with country hover/click, provider-backed network points and provider-backed corporate/branch locations.
- Explicit separation between IP/network geography and corporate branch geography; the engine never invents a company branch from an IP centroid.
- DomainTools integration adapter for Domain Profile, WHOIS Lookup and Iris Investigate when a licensed API key is configured.
- DomainTools web pivots are always available as navigation links even when the API connector is not configured.
- Expanded provider catalog entries for DomainTools Iris products.
- V22 defensive C2/malware-infrastructure correlation remains passive/provider-backed.

## Evidence policy

A domain does not physically "live" in a country. The system reports separate evidence classes:

1. Registry / registrar jurisdiction data.
2. Current IP/network geolocation.
3. Provider-backed corporate locations / branches.
4. DNS infrastructure locations.

These are never silently conflated.
