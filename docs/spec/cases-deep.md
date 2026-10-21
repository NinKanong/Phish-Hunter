# cases — Deep Capability Contract

Sections: 7  
Capability fields: 61

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
### CASE OVERVIEW
- Case ID
- Case title
- Case description
- Case status (new, triage, investigating, contained, closed, FP)
- Priority (P1-P4)
- Severity (critical, high, medium, low, info)
- SLA deadline
- Assignee
- Watchers
- Tags
- Custom fields
- Created at
- Updated at
- Verdict
### CASE EVIDENCE
- Every linked scan
- Every linked report
- Every linked IOC
- Every linked file
- Every linked email
- Every linked URL
- Every linked PCAP
- Every linked sandbox run
- Chain of custody
- Immutable audit log
- Verdict
### CASE TIMELINE
- Every event chronologically
- Every action by every user
- Every state change
- Every comment
- Every attachment
- Verdict
### CASE COLLABORATION
- Every comment (threaded)
- Every @mention
- Every attachment
- Every watcher
- Every notification
- Verdict
### CASE WORKFLOW
- Kanban board
- List view
- Calendar view
- Bulk actions
- Templates (phishing, malware, BEC)
- Playbooks (automated steps)
- Verdict
### CASE REPORTING
- Case summary
- Timeline
- IOCs
- Recommendations
- Export PDF
- Export DOCX
- Export STIX
- Send to SIEM/SOAR
- Verdict
### CASE METRICS
- MTTD (mean time to detect)
- MTTR (mean time to respond)
- MTTA (mean time to acknowledge)
- Analyst productivity
- SLA compliance
- False positive rate
- Verdict
- ---