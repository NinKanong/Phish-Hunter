# PCAP Analyst (Network Artifacts)

Deep network-forensics module for PCAP/PCAPNG and sibling telemetry. Keep new logic isolated by layer:

- `parsers/` packet and log parsing
- `analyzers/` protocol-specific analysis
- `enrichment/` external context providers
- `correlation/` cross-artifact relationships
- `incident_response/` containment/response workflow
- `ai/` evidence-grounded AI orchestration
- `reporting/` analyst/export formats
- `workers/` asynchronous processing
- `api.py` HTTP/WebSocket boundary
- `orchestrator.py` investigation pipeline
- `manifest.py` rebuild contract
