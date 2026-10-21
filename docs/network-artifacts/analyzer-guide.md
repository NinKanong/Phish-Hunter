# Network Artifact Analyzer Guide

## PCAP
Uses the existing passive K4 packet parser for classic PCAP and PCAPNG, producing packet metadata, flows, DNS observations, HTTP metadata, TLS SNI, IOCs, host profiles and passive behavioral candidates.

## Zeek
Parses `#fields` TSV logs and normalizes connection, DNS, HTTP, SSL/TLS, SMB and Kerberos observations based on the filename.

## Suricata
Parses newline-delimited EVE JSON and preserves event type, flow data, alert signature, severity and network endpoints.

## NetFlow/IPFIX
Accepts CSV or JSON records and normalizes five-tuple and volume fields.

## Other logs
Firewall, proxy, DNS and DHCP text/JSON logs are normalized through a bounded generic parser. Provider-specific parsers can be added behind the same event schema without changing the frontend contract.
