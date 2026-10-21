# PhishGuard Analysis Engine

PhishGuard is intentionally static-first. The web process never executes an uploaded sample.

## File analysis

The static engine calculates independent cryptographic hashes, byte entropy, printable/null ratios, strings, IOC candidates, file-type signatures, filename anomalies, archive metadata, Office/OOXML structures, PDF active-content markers, script behavior markers, packer markers, PE structure, import metadata, Windows API signal classes, PE security flags, anti-analysis markers and optional YARA matches.

For PE files the engine reports architecture, timestamp, entry point, image base, sections, per-section entropy, section characteristics, import directory, DLLs/functions, certificate-table presence and overlay size. Import names are converted to evidence signals such as process injection, memory allocation, payload transfer and debugger detection. These are evidence markers rather than proof of runtime behavior.

## Email analysis

The email parser reads RFC 5322/MIME structure, Received headers, sender/reply/return-path relationships, Authentication-Results, DKIM-Signature presence, links, visible-link mismatches, forms, credential fields, tracking pixels and attachments. Authentication results are reported as message-supplied evidence, not independently verified mail-server truth.

## URL analysis

The URL collector validates every hostname before connection, rejects private/loopback/link-local/metadata destinations, resolves the destination to an IP, pins the socket to the checked address and revalidates every redirect. It collects DNS, TLS, HTTP response metadata, security headers, page links, forms, scripts and phishing signals without launching browser JavaScript.

## Correlation

IOC counts, unique domains/IPs/hashes, ATT&CK-oriented techniques, evidence clusters and investigation posture are combined into an analyst-facing correlation object. Actor attribution is deliberately withheld unless independent campaign-level evidence exists.

## External intelligence

VirusTotal and urlscan.io connectors are real HTTP integrations when API keys are configured. Other providers in the catalog are declared integration targets but do not return fabricated data.

## Dynamic analysis boundary

A separately isolated sandbox can be integrated through `phishhunter/sandbox/manager.py`. The default system does not execute files and does not treat a sandbox placeholder as successful detonation. A production detonation environment should be a dedicated isolated host or microVM boundary with no access to application credentials or tenant secrets.


## K4 v12 IR Workbench
The Network Artifacts workspace now includes an interactive attack graph, victim/endpoint pivots, kill-chain timeline, bounded packet-level forensic drill-down, C2/beaconing analysis, exfiltration tracking, DNS intelligence, threat-intelligence evidence ledger, response blocklist generation, analyst disposition notes, chain-of-custody metadata, and executive/forensic reporting. The analysis remains passive and attribution is explicitly treated as a hypothesis requiring corroboration.
