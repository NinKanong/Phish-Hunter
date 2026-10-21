# graph — Deep Capability Contract

Sections: 5  
Capability fields: 45

## Universal requirements
### Evidence
- raw evidence
- interpretation
- source reference
- first seen / last seen
### Confidence
- 0-100 calibrated confidence
- confidence rationale
### Threat Intelligence
- configured-provider lookups
- lookup timestamps
- provider status
### Timeline
- event timestamp
- observation timestamp
- first/last seen
### Correlation
- related findings
- related IOCs
- graph pivot identifiers
### MITRE ATT&CK
- technique ID
- technique name
- evidence reference
- confidence
### Reporting
- raw evidence appendix
- machine-readable result
- analyst report
- self-verification

## Deep sections
### GRAPH OVERVIEW
- Total nodes
- Total edges
- Node types (IOC, campaign, actor, malware, TTP)
- Edge types (resolves_to, hosts, redirects_to, drops, contacts,
- │ uses, attributed_to, targets, related_to, shares_cert,
- │ shares_favicon, shares_ip)
- Verdict
### GRAPH VISUALIZATION
- Interactive Cytoscape graph
- Node size = importance
- Node color = verdict
- Edge thickness = confidence
- Filter by entity type
- Filter by confidence
- Expand node (load neighbors)
- Shortest path between two IOCs
- Cluster detection
- Community detection
- Timeline overlay
- Verdict
### GRAPH ANALYSIS
- Centrality metrics (degree, betweenness, closeness, eigenvector)
- Community detection (Louvain, Leiden)
- Clustering coefficient
- PageRank
- Shortest paths
- Connected components
- Anomaly detection
- Verdict
### GRAPH EXPORT
- GraphML
- GEXF
- DOT
- Mermaid
- SVG
- PNG
- JSON
- Verdict
### GRAPH QUERIES
- Pivot by IOC
- Pivot by campaign
- Pivot by actor
- Pivot by malware family
- Pivot by infrastructure
- Find all IOCs seen with this IOC
- Find all campaigns using this IOC
- Find all actors using this IOC
- Verdict
- ---