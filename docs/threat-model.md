# Threat model

Primary threats: SSRF, malicious uploads, credential theft, cross-tenant access, denial of service, data exfiltration, and accidental malware execution. Controls include URL guard, upload guard, tenant filters, rate limiting at the edge, and a hard boundary around dynamic sandbox execution.
