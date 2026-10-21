# PCAP Analyst rebuild map

Keep the implementation split by responsibility:

- `parsers/` packet/log parsing
- `analyzers/` protocol-specific analyzers
- `enrichment/` external context
- `correlation/` multi-artifact relationships
- `incident_response/` containment/response workflow
- `ai/` evidence-grounded AI orchestration
- `reporting/` analyst and export formats
- `workers/` asynchronous processing
- `api.py` HTTP/WebSocket boundary
- `orchestrator.py` investigation pipeline
