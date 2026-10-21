from __future__ import annotations
STAGES=[
 ('normalize','Normalize URL/domain and registered-domain boundary'),('url_anatomy','Decompose scheme, authority, host, port, path, query and fragment'),
 ('encoding','Decode bounded encoding and obfuscation layers'),('domain_anatomy','Analyze labels, suffix, IDN, script and randomness'),
 ('rdap','Resolve registration lifecycle and registry entities'),('dns','Collect full current DNS matrix'),('dns_auth','Analyze SPF, DKIM, DMARC, BIMI, MTA-STS and TLS-RPT'),
 ('dnssec','Evaluate DNSSEC, CAA and delegation posture'),('historical_dns','Correlate passive-DNS history when configured'),('ct','Correlate certificate transparency and SANs'),
 ('subdomains','Enumerate discovered subdomains from passive sources'),('network','Correlate IP, PTR, ASN, netblock and hosting'),('geo','Build provider-backed system locations'),
 ('http','Inspect HTTP/TLS/headers/cookies/forms safely'),('services','Normalize service and banner observations'),('technology','Fingerprint web/application technologies'),
 ('reputation','Fuse independent reputation sources'),('breach','Query authorized breach providers'),('osint','Generate evidence-backed investigation pivots'),
 ('security','Run homograph, typosquat, takeover, DGA and DNS-tunnel heuristics'),('correlation','Build entity-resolution and relationship families'),
 ('graph','Build typed relationship graph'),('scoring','Calibrate ten-dimensional risk'),('reasoning','Generate evidence-grounded AI reasoning'),
 ('monitoring','Prepare continuous-watch plan'),('evidence','Hash evidence artifacts'),('reporting','Build export-ready case package')]

def plan()->list[dict]: return [{'stage':k,'description':d,'phase':i+1,'state':'planned'} for i,(k,d) in enumerate(STAGES)]
