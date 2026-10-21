# V20 Architecture

```text
Browser
  |
  +--> POST /services/url-domain-analyst/scan
  |       |
  |       +--> in-process job queue
  |               |
  |               +--> worker thread / async engine
  |                       |
  |                       +--> normalized target
  |                       +--> bounded public collection
  |                       +--> deep evidence correlation
  |                       +--> risk / graph / evidence / OSINT
  |
  +--> GET /services/url-domain-analyst/scan/{job}/events
  |       +--> live SSE progress
  |
  +--> GET /services/url-domain-analyst/scan/{job}/result
          +--> normalized investigation dossier
```

## Collection layers

- Intake: URL/domain parsing, IDNA, registered-domain normalization.
- DNS: A/AAAA/CNAME/MX/NS/TXT and DNS-security observations.
- Registration: RDAP lifecycle and registrar/entity evidence.
- Certificate: CT names, certificates and reuse relationships.
- Web: bounded HTTP metadata, redirects, headers, forms, links and technology signals.
- Infrastructure: IP, ASN, hosting, CDN/WAF, cloud and system-location observations.
- Threat: provider reputation, phishing/malware exposure, abuse and breach status.
- OSINT: search/archive/code/document/company pivots as source-aware plans.
- Correlation: entities, relationships, graph, timeline and evidence ledger.
- Reasoning: explainable risk, confidence, limitations and analyst task plan.
