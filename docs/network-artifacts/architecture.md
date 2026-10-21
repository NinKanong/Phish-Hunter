# PCAP Analyst — Network Artifacts Architecture

This subsystem is deliberately isolated to the **PCAP Analyst** service. Other Cyber-Phish-k4 analyst services are not changed by the Network Artifacts workflow.

## Artifact siblings

- PCAP / PCAPNG
- Zeek logs
- Suricata EVE JSON
- NetFlow / IPFIX CSV or JSON
- Firewall logs
- Proxy logs
- DNS server logs
- DHCP logs

## Flow

```text
React + TypeScript
  Upload Center / Dashboard / IOC Explorer / Timeline / Graph / Report
              |
              | REST + WebSocket
              v
FastAPI /api/v1/pcap
  upload -> job -> status -> iocs -> artifacts -> report
              |
              v
K4 Network Artifact Controller
  triage -> parse -> correlate -> detect -> enrich -> MITRE -> timeline -> report
              |
              +--> PCAP parser (existing passive packet engine)
              +--> Zeek parser
              +--> Suricata EVE parser
              +--> NetFlow/IPFIX parser
              +--> firewall/proxy/DNS/DHCP parser
              |
              v
Correlation + Detection
  PCAP <-> Zeek
  NetFlow <-> Suricata
  IP <-> hostname
  IOC <-> configured intelligence providers
              |
              v
Evidence / Timeline / IOC / Graph / Report
```

## Security boundary

Uploaded network artifacts are parsed as data. The local service does not execute payloads, deliver exploits, actively scan destinations, or claim attribution from network-only evidence.

External intelligence providers are connector boundaries. A provider is never reported as queried unless a configured integration returns a result.
