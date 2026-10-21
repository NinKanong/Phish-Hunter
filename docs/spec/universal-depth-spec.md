# UNIVERSAL DEPTH RULES (Add to Section A)

markdown

```
## SECTION A.1 — DEPTH CONTRACT (UNIVERSAL, ALL SERVICES)

Every service in Cyber-Phish-k4 MUST produce findings in this format:

  FINDING
    ├─ What was found (concise)
    ├─ Raw evidence (byte offset, DNS record, HTTP header, TLS handshake,
    │   certificate field, string, import, section, registry key, process,
    │   network flow, registry hive, log line, etc.)
    ├─ Interpretation (why it matters — human-readable)
    ├─ MITRE ATT&CK technique (ID + name) with evidence
    ├─ Confidence (0-100)
    ├─ Threat intel lookup result (source + verdict + date)
    ├─ First seen / last seen
    └─ Related IOCs (with pivot links)

Every service MUST produce:

1. **Raw evidence** — never a summary alone. Every claim has a raw artifact.
2. **Interpretation** — never raw evidence alone. Every artifact is explained.
3. **MITRE mapping** — every technique has evidence (which import, string,
   header, flow, syscall, etc. triggered it).
4. **Confidence score** — 0-100 per finding, calibrated.
5. **Cross-references** — every finding links to related findings in the
   same report and across reports (via Neo4j graph).
6. **Threat intel enrichment** — every IOC looked up in every configured
   source with timestamps.
7. **Timeline** — every finding timestamped (when it happened, when it
   was observed, when it was first/last seen by threat intel).
8. **Export** — every service's output exported in 30+ formats (PDF,
   HTML, DOCX, XLSX, PPTX, JSON, XML, YAML, CSV, STIX 2.1, MISP, SARIF,
   YARA, Sigma, Suricata, Snort, KQL, SPL, EQL, blocklists, GraphML,
   MITRE Navigator, etc.).
9. **Raw evidence appendix** — hex dumps, raw headers, raw JSON, raw
   PCAP excerpts, screenshots, byte-offset tables.
10. **Self-verification** — before finalizing, the service verifies every
    field is populated, every finding has evidence, no "N/A" without
    reason, no "TODO", no "example", no "sample".

FORBIDDEN in any output:
  - "PASS" / "FAIL" without explanation
  - "OK" without evidence
  - "N/A" without reason
  - "TODO", "sample", "example", "placeholder"
  - Summaries without raw evidence
  - Empty sections
  - Checkbox-only reporting

REQUIRED in every output:
  - Raw evidence for every finding
  - Interpretation for every raw artifact
  - MITRE technique for every attack behavior
  - Confidence for every finding
  - Threat intel for every IOC
  - Timeline entry for every event
  - Export in all 30+ formats
  - Raw evidence appendix
```

svgsvg

---

# PART 2 — PER-SERVICE DEPTH SPECIFICATIONS

## 2.1 — EMAIL ANALYST (Deep)

text

```
EMAIL OVERVIEW
  ├─ File format (EML / MSG / MBOX / PST / EMLX / MHT)
  ├─ File size
  ├─ Message size (decoded)
  ├─ Message ID
  ├─ Subject (decoded + raw)
  ├─ Date (parsed + raw + timezone + UTC)
  ├─ From (display name + address + raw)
  ├─ To (every recipient with display name + address)
  ├─ CC, BCC (every recipient)
  ├─ Reply-To (address + mismatch check)
  ├─ Return-Path (address + mismatch check)
  ├─ Sender (address + mismatch check)
  ├─ Envelope-From (from SMTP)
  ├─ Envelope-To (from SMTP)
  ├─ X-Mailer / User-Agent
  ├─ MIME-Version
  ├─ Content-Type
  ├─ Content-Transfer-Encoding
  ├─ Priority / Importance / X-Priority
  ├─ Language (detected + confidence)
  ├─ Attachment count
  ├─ URL count
  ├─ Embedded image count
  ├─ Tracking pixel count
  └─ Verdict: legitimate / spam / phishing / BEC / malware

HEADER ANALYSIS (every header, every value)
  For EVERY header:
  ├─ Header name
  ├─ Raw value
  ├─ Parsed value
  ├─ RFC compliance (valid / malformed)
  ├─ Interpretation (why it matters)
  ├─ Suspicious flag (yes/no)
  └─ Cross-reference with other headers

RECEIVED CHAIN (every hop)
  For EVERY hop:
  ├─ Hop number
  ├─ From hostname + IP
  ├─ By hostname + IP
  ├─ With protocol (SMTP, ESMTP, ESMTPS, ESMTPSA)
  ├─ ID
  ├─ Timestamp (raw + UTC)
  ├─ Delay from previous hop (seconds)
  ├─ Cumulative delay
  ├─ IP geolocation (country, city)
  ├─ ASN + ASN name
  ├─ Reverse DNS
  ├─ IP reputation (AbuseIPDB, IPQS, GreyNoise)
  ├─ SPF result at this hop
  ├─ DKIM result at this hop
  ├─ DMARC result at this hop
  ├─ TLS info (version, cipher, cert)
  ├─ Anomalies (delay > 60s, private IP after public, etc.)
  └─ Verdict per hop

AUTHENTICATION (deep)
  SPF:
  ├─ Envelope-from domain
  ├─ SPF record (raw TXT)
  ├─ DNS lookups used (of 10)
  ├─ Every mechanism evaluated (a, mx, ip4, ip6, include, exists, ptr, all)
  ├─ Match result (pass / fail / softfail / neutral / none / permerror)
  ├─ Qualifier (~all, -all, ?all, +all)
  ├─ Explanation
  ├─ Sending IP vs SPF record
  ├─ include resolution (every IP)
  ├─ Historical SPF changes
  └─ Verdict

  DKIM:
  ├─ Every DKIM-Signature header
  ├─ Selector
  ├─ Domain (d=)
  ├─ Algorithm (rsa-sha256, ed25519-sha256)
  ├─ Canonicalization (relaxed/relaxed, simple/simple)
  ├─ Body hash (bh=)
  ├─ Header hash (b=)
  ├─ Public key DNS TXT record
  ├─ Signature verification (pass / fail / permfail / temperror)
  ├─ Signed headers list (h=)
  ├─ Timestamp (t=)
  ├─ Expiration (x=)
  ├─ Body length (l=)
  ├─ Verification error (if any)
  └─ Verdict

  DMARC:
  ├─ DMARC record (raw TXT)
  ├─ Policy (p=none / quarantine / reject)
  ├─ Subdomain policy (sp=)
  ├─ Alignment mode (adkim, aspf: r or s)
  ├─ Aggregate report URI (rua=)
  ├─ Forensic report URI (ruf=)
  ├─ SPF alignment (pass / fail)
  ├─ DKIM alignment (pass / fail)
  ├─ DMARC result (pass / fail / none / temperror)
  ├─ Lookalike domain confidence
  └─ Verdict

  ARC:
  ├─ ARC-Seal
  ├─ ARC-Message-Signature
  ├─ ARC-Authentication-Results
  ├─ Chain validation (pass / fail)
  ├─ Instance number
  ├─ Signer
  └─ Verdict

  BIMI:
  ├─ BIMI record (raw TXT)
  ├─ Logo URL
  ├─ VMC (Verified Mark Certificate)
  ├─ Certificate validity
  └─ Verdict

  MTA-STS:
  ├─ MTA-STS TXT record
  ├─ Policy file (fetched)
  ├─ Mode (enforce / testing / none)
  └─ Verdict

  DANE/TLSA:
  ├─ TLSA record
  ├─ Certificate match
  └─ Verdict

SENDER ANALYSIS
  Sender domain:
  ├─ Registered domain
  ├─ Domain age (WHOIS)
  ├─ Registrar
  ├─ Nameservers
  ├─ Privacy protection
  ├─ Historical WHOIS changes
  ├─ Domain reputation
  ├─ Lookalike of known brands (Levenshtein, homoglyph)
  └─ Verdict

  Sender IP:
  ├─ Every sending IP from Received chain
  ├─ ASN + ASN name
  ├─ Geolocation (country, city, coordinates)
  ├─ Reverse DNS
  ├─ Reputation (AbuseIPDB score, IPQS risk, GreyNoise class)
  ├─ Open ports (via Shodan/Censys if key)
  ├─ Blocklist status (Spamhaus, Barracuda, SORBS, etc.)
  ├─ Historical activity
  └─ Verdict

  Infrastructure:
  ├─ Mail server hostname
  ├─ Mail server software (Postfix, Exim, Sendmail)
  ├─ TLS version
  ├─ TLS cipher
  ├─ Certificate (issuer, subject, validity)
  ├─ HELO/EHLO name
  ├─ HELO/EHLO validation
  └─ Verdict

CONTENT ANALYSIS
  Subject:
  ├─ Raw
  ├─ Decoded (MIME encoded-word)
  ├─ Language
  ├─ Urgency score
  ├─ Threat score
  ├─ Manipulation score
  ├─ Brand impersonation score
  ├─ Keyword matches (from phishing keyword list)
  └─ Verdict

  Body (plain text):
  ├─ Full text
  ├─ Language
  ├─ Urgency score
  ├─ Threat score
  ├─ Manipulation score
  ├─ Sentiment
  ├─ Every URL extracted (defanged)
  ├─ Every email address
  ├─ Every phone number
  ├─ Every crypto wallet address
  ├─ Every Telegram/WhatsApp link
  ├─ Every sentence with urgency keywords highlighted
  └─ Verdict

  Body (HTML):
  ├─ Raw HTML
  ├─ Sanitized HTML (for safe rendering)
  ├─ Every <a> tag (href, text, mismatch check)
  ├─ Every <form> (action, method, every field)
  ├─ Every <img> (src, alt, tracking pixel check)
  ├─ Every <script> (external + inline)
  ├─ Every CSS rule (hidden text, offscreen, tiny fonts)
  ├─ Hidden text detection (white-on-white, zero-width, RTL override)
  ├─ Invisible form detection
  ├─ Overlay trick detection
  ├─ Tracking pixel detection (1x1, unique URL)
  ├─ Web bug detection
  ├─ Base64-encoded content decoded
  ├─ Hex-encoded content decoded
  ├─ ROT13 / JS obfuscation detection
  ├─ Every external resource
  └─ Verdict

  Links:
  ├─ Every URL (raw + defanged)
  ├─ Anchor text
  ├─ Anchor text vs href mismatch check
  ├─ Redirect chain (if resolvable)
  ├─ Domain reputation
  ├─ URL risk score
  ├─ Typo-squatting check
  ├─ Homoglyph check
  └─ Verdict per URL

  Forms:
  ├─ Every <form>
  ├─ Action URL (internal / external)
  ├─ Method (GET / POST)
  ├─ Every field (name, type, placeholder, required, pattern)
  ├─ Password fields
  ├─ Credit card fields
  ├─ OTP fields
  ├─ Hidden fields
  ├─ CSRF token presence
  ├─ Brand match
  └─ Verdict

  Social Engineering:
  ├─ Urgency phrases ("urgent", "immediate action", "account suspended")
  ├─ Threat phrases ("account will be closed", "legal action")
  ├─ Authority phrases ("CEO", "IT department", "bank")
  ├─ Reward phrases ("prize", "bonus", "refund")
  ├─ Fear phrases ("hacked", "compromised", "unusual activity")
  ├─ Trust phrases ("verified", "official", "secure")
  ├─ Every matched phrase with position
  └─ Verdict

URL ANALYSIS (within email)
  For EVERY URL:
  ├─ Raw URL
  ├─ Defanged URL
  ├─ Scheme, host, path, query, fragment
  ├─ Domain age
  ├─ Domain reputation
  ├─ IP resolution
  ├─ ASN
  ├─ Geolocation
  ├─ SSL certificate
  ├─ Redirect chain
  ├─ Final URL
  ├─ Screenshot (if resolvable)
  ├─ Brand impersonation check
  ├─ Phishing kit detection
  ├─ Threat intel lookup (VT, URLScan, GSB, PhishTank, OpenPhish)
  └─ Verdict per URL

ATTACHMENT ANALYSIS
  For EVERY attachment:
  ├─ Filename (raw + decoded)
  ├─ Filename anomaly (double extension, RTLO, unicode tricks)
  ├─ MIME type (declared)
  ├─ MIME type (magic bytes)
  ├─ MIME type mismatch check
  ├─ Size
  ├─ Hashes (MD5, SHA1, SHA256, ssdeep, TLSH)
  ├─ File type (TRID)
  ├─ Metadata (author, company, created, modified)
  ├─ Macro detection (VBA, XLM, Excel 4.0)
  ├─ OLE extraction
  ├─ PDF JS extraction
  ├─ Embedded file extraction
  ├─ Password-protected archive detection
  ├─ Password brute-force (10,000 common passwords)
  ├─ Nested archive extraction (10 levels)
  ├─ Every extracted file → FILE ANALYZER (recursive)
  ├─ Threat intel lookup
  └─ Verdict per attachment

IOC EXTRACTION
  ├─ Every IP (defanged)
  ├─ Every domain (defanged)
  ├─ Every URL (defanged)
  ├─ Every hash (MD5/SHA1/SHA256)
  ├─ Every email address
  ├─ Every crypto wallet
  ├─ Every Telegram bot token
  ├─ Every Discord webhook
  ├─ Every Slack webhook
  ├─ Every mutex
  ├─ Every registry key
  ├─ Every file path
  └─ Deduplicated with confidence + first/last seen

THREAT INTELLIGENCE
  For EVERY IOC:
  ├─ VirusTotal (every engine)
  ├─ URLScan.io
  ├─ Google Safe Browsing
  ├─ Microsoft SmartScreen
  ├─ PhishTank
  ├─ OpenPhish
  ├─ URLhaus
  ├─ Spamhaus
  ├─ AlienVault OTX
  ├─ AbuseIPDB
  ├─ IPQualityScore
  ├─ GreyNoise
  ├─ MISP (internal)
  ├─ OpenCTI (internal)
  └─ Aggregate verdict

PHISHING DETECTION (ML)
  ├─ Classifier score (0-100)
  ├─ Verdict (phishing / BEC / spam / legitimate)
  ├─ Feature importance (top 20 features)
  ├─ Similar past phishing samples (vector search)
  └─ Campaign attribution

RISK SCORE
  ├─ Score: 0-100
  ├─ Verdict: Malicious / Suspicious / Clean / Unknown
  ├─ Confidence: 0-100
  ├─ Every signal with weight + contribution
  ├─ Top contributing signals
  ├─ Counter-signals
  └─ Explanation paragraph

MITRE ATT&CK
  ├─ Every technique identified
  ├─ Technique ID + name + tactic
  ├─ Evidence per technique
  ├─ Confidence per technique
  └─ Sub-techniques

EVIDENCE
  ├─ Raw headers (full)
  ├─ Raw body (plain + HTML)
  ├─ Raw attachments (with hashes)
  ├─ Raw Received chain
  ├─ Raw auth results
  ├─ Raw URLs (defanged)
  ├─ Raw IOCs
  └─ Screenshots

TIMELINE
  ├─ Email sent (from Date header)
  ├─ Every hop timestamp
  ├─ Every URL resolution
  ├─ Every threat intel lookup
  ├─ Every file scan
  └─ Chronological view

INVESTIGATION REPORT
  ├─ All sections above
  ├─ 30+ export formats
  ├─ Raw evidence appendix
  └─ Self-verification passed

---

## 2.2 — URL ANALYST (Deep)

(Same level of depth. Every field listed in the earlier Part 2 of the previous response — URL parsing, domain analysis, DNS, IP, SSL/TLS, HTTP, rendered page, JS analysis, form analysis, brand impersonation, content, trackers, tech stack, reputation, IOC extraction, MITRE, risk score, report.)

Plus new additions:
  ├─ **Full redirect chain** with every hop:
  │   ├─ Hop number
  │   ├─ URL
  │   ├─ Status code
  │   ├─ Location header
  │   ├─ Set-Cookie headers
  │   ├─ Server header
  │   ├─ X-Powered-By
  │   ├─ Timing (DNS, TCP, TLS, TTFB, download)
  │   ├─ Response size
  │   ├─ Content-Type
  │   ├─ Anomalies
  │   └─ Verdict per hop
  ├─ **JavaScript execution trace** (Playwright):
  │   ├─ Every network request (method, URL, headers, body)
  │   ├─ Every console log
  │   ├─ Every error
  │   ├─ Every DOM mutation
  │   ├─ Every cookie set
  │   ├─ Every localStorage / sessionStorage write
  │   ├─ Every WebSocket connection
  │   ├─ Every fetch/XHR call
  │   └─ Every form submission attempt
  ├─ **Anti-analysis detection**:
  │   ├─ navigator.webdriver check
  │   ├─ debugger statement
  │   ├─ devtools detection
  │   ├─ screen / window size checks
  │   ├─ WebGL fingerprinting
  │   ├─ Canvas fingerprinting
  │   ├─ Audio fingerprinting
  │   ├─ Timezone checks
  │   ├─ Language checks
  │   ├─ Plugin checks
  │   └─ Verdict per check
  ├─ **Crypto-mining detection**:
  │   ├─ CoinHive / CryptoLoot / Coinhive-clone scripts
  │   ├─ WebAssembly miner
  │   ├─ Web Worker miner
  │   ├─ Wallet address extracted
  │   ├─ Mining pool URL
  │   └─ Verdict
  ├─ **QR code extraction**:
  │   ├─ Every QR code in every image
  │   ├─ Decoded content
  │   ├─ URL / text / WiFi / vCard
  │   └─ Verdict
  ├─ **Brand template comparison**:
  │   ├─ Every brand template compared (500+)
  │   ├─ SSIM score per template
  │   ├─ Perceptual hash distance
  │   ├─ Favicon mmh3 match
  │   ├─ Logo detection (ViT confidence)
  │   ├─ Title match
  │   ├─ Copyright text match
  │   ├─ Layout similarity
  │   ├─ Color palette similarity
  │   ├─ Top 5 matches with scores
  │   └─ Verdict

---

## 2.3 — FILE ANALYST (Deep)

(Same depth as before, plus:)

FILE IDENTIFICATION
  ├─ Original filename
  ├─ Filename anomaly (double extension, RTLO, unicode tricks, homoglyph)
  ├─ File size (bytes, KB, MB)
  ├─ Extension
  ├─ MIME (claimed)
  ├─ MIME (magic bytes)
  ├─ MIME (TRID)
  ├─ MIME (libmagic)
  ├─ MIME mismatch check
  ├─ File type confidence
  ├─ MD5, SHA1, SHA256, SHA512
  ├─ ssdeep
  ├─ TLSH
  ├─ imphash (PE)
  ├─ authentihash (PE)
  ├─ Rich header hash (PE)
  ├─ Section hashes (PE/ELF/Mach-O)
  ├─ Fuzzy hash neighbors (in local DB)
  ├─ First seen (VirusTotal)
  ├─ Last seen (VirusTotal)
  └─ Verdict

FILE METADATA
  ├─ Created
  ├─ Modified
  ├─ Accessed
  ├─ Author
  ├─ Company
  ├─ Producer
  ├─ Creator
  ├─ Last saved by
  ├─ Revision number
  ├─ Template
  ├─ Custom properties (every one)
  ├─ EXIF (images)
  ├─ GPS coordinates (if present)
  ├─ Camera make/model (if present)
  └─ Verdict

FILE STRUCTURE (deep)
  ├─ Every section/stream/segment
  ├─ Every chunk/atom/box
  ├─ Every table (import, export, resource, reloc, debug, TLS)
  ├─ Every directory entry
  ├─ Every string table
  ├─ Every header field with offset + raw bytes
  ├─ Overlay (offset, size, entropy, carved)
  ├─ Header checksum validation
  ├─ Structural anomalies
  └─ Verdict

STRINGS (deep)
  ├─ ASCII strings (min 4, deduplicated, categorized):
  │   ├─ URLs (with defang + threat intel)
  │   ├─ Domains
  │   ├─ IPs
  │   ├─ Email addresses
  │   ├─ Windows paths
  │   ├─ Unix paths
  │   ├─ Registry keys
  │   ├─ Mutex names
  │   ├─ Named pipes
  │   ├─ User agents
  │   ├─ API endpoints
  │   ├─ Command lines
  │   ├─ Crypto wallet addresses
  │   ├─ Base64 blobs (>40 chars, decoded + re-scanned)
  │   ├─ Hex blobs
  │   ├─ SQL queries
  │   ├─ Error messages
  │   ├─ Encryption constants
  │   ├─ Shellcodes
  │   └─ C2 indicators
  ├─ Unicode strings (UTF-16LE/BE)
  ├─ Stack strings (emulated)
  ├─ Tight strings
  ├─ FLOSS strings
  └─ Each string: offset, encoding, category, threat score

ENTROPY (deep)
  ├─ Whole-file entropy
  ├─ Per-section entropy
  ├─ Per-chunk entropy (16-byte windows)
  ├─ Entropy chart data
  ├─ High-entropy regions (>7.5) with offsets
  ├─ Low-entropy regions (<1.0) with offsets
  ├─ Compression/encryption indicators
  └─ Packer likelihood score

EMBEDDED OBJECTS
  ├─ Every embedded file extracted
  ├─ Every nested archive extracted (10 levels)
  ├─ Every OLE object extracted
  ├─ Every PDF attachment extracted
  ├─ Every macro extracted
  ├─ Every resource extracted
  ├─ Every image extracted
  ├─ Every script extracted
  ├─ Every extracted file → recursively analyzed
  └─ Verdict per extracted object

PE ANALYSIS (deep)
  DOS header: every field
  NT headers: every field
  File header:
    ├─ Machine
    ├─ Number of sections
    ├─ Timestamp (raw + UTC, anomaly check)
    ├─ Characteristics (every flag)
    └─ Pointer to symbol table
  Optional header:
    ├─ Magic
    ├─ Entry point
    ├─ Image base
    ├─ Section alignment
    ├─ File alignment
    ├─ Subsystem
    ├─ DllCharacteristics (every flag)
    ├─ Size of stack/heap reserve/commit
    ├─ Checksum (validate)
    └─ Number of RVA and sizes
  Every section:
    ├─ Name
    ├─ Virtual address
    ├─ Virtual size
    ├─ Raw pointer
    ├─ Raw size
    ├─ Characteristics (every flag)
    ├─ Entropy
    ├─ MD5
    ├─ SHA256
    ├─ Suspicious strings
    ├─ Suspicious imports
    └─ Verdict
  Every import:
    ├─ DLL name
    ├─ Function name (or ordinal)
    ├─ Resolved address
    ├─ Category
    ├─ MITRE technique
    ├─ Suspicion score
    └─ Evidence
  Every export:
    ├─ Name
    ├─ Ordinal
    ├─ RVA
    ├─ Forwarder
    └─ Suspicion
  Every resource:
    ├─ Type
    ├─ Name
    ├─ Language
    ├─ Size
    ├─ Hash
    ├─ Extracted content
    ├─ Nested PE detection
    └─ Verdict
  Manifest:
    ├─ Requested execution level
    ├─ DPI awareness
    ├─ UAC settings
    ├─ Supported OS
    └─ Verdict
  Rich header:
    ├─ Every build ID
    ├─ Checksum
    ├─ Anomalies
    └─ Verdict
  Debug directory:
    ├─ PDB path
    ├─ GUID
    ├─ Age
    ├─ Timestamp
    └─ Verdict
  Authenticode:
    ├─ Signature present
    ├─ Signer
    ├─ Issuer
    ├─ Cert chain
    ├─ Validity
    ├─ Timestamp (RFC 3161)
    ├─ Revocation (OCSP + CRL)
    ├─ Algorithm
    ├─ Chain validation
    ├─ Counter-signatures
    ├─ Anomalies
    └─ Verdict

ELF ANALYSIS (deep) — every field
MACH-O ANALYSIS (deep) — every field
.NET ANALYSIS (deep) — every field
OFFICE ANALYSIS (deep) — every field
PDF ANALYSIS (deep) — every field
SCRIPT ANALYSIS (deep) — every field
ARCHIVE ANALYSIS (deep) — every field
APK ANALYSIS (deep) — every field
IPA ANALYSIS (deep) — every field
FIRMWARE ANALYSIS (deep) — every field

YARA (deep)
  For EVERY rule match:
  ├─ Rule name
  ├─ Author
  ├─ Description
  ├─ Reference
  ├─ Tags
  ├─ Every matched string (offset, length, context, hex)
  ├─ Rule severity
  ├─ Rule category
  └─ Verdict

CAPA (deep)
  For EVERY capability:
  ├─ Capability name
  ├─ MITRE ATT&CK technique
  ├─ MBC mapping
  ├─ Function addresses
  ├─ Matching features (strings, APIs, numbers)
  ├─ Confidence
  └─ Verdict

CONFIGURATION EXTRACTION (deep)
  For EVERY family detected:
  ├─ Family name
  ├─ Config type
  ├─ Decryption method
  ├─ Every C2 server
  ├─ Encryption keys
  ├─ Bot tokens
  ├─ Discord webhooks
  ├─ SMTP credentials
  ├─ FTP credentials
  ├─ Bitcoin wallets
  ├─ Campaign IDs
  ├─ Build IDs
  └─ Verdict

THREAT INTELLIGENCE (deep)
  For EVERY IOC:
  ├─ VirusTotal (every engine + result + version + date)
  ├─ MalwareBazaar (family + tags + first seen + signature)
  ├─ ThreatFox (family + confidence + reference + date)
  ├─ Hybrid Analysis (verdict + family + score + date)
  ├─ Joe Sandbox (verdict + family + score + date)
  ├─ ANY.RUN (verdict + family + tags + date)
  ├─ Triage (verdict + family + score + date)
  ├─ Internal cache (prior sightings)
  └─ Aggregate verdict

BEHAVIORAL PREDICTION (deep)
  ├─ Based on imports + strings + entropy + structure
  ├─ Likely behavior 1 with evidence + confidence
  ├─ Likely behavior 2 with evidence + confidence
  ├─ ... (every predicted behavior)
  └─ Verdict

IOC EXTRACTION (deep)
  ├─ Every IP (defang + first/last seen + confidence)
  ├─ Every domain (defang + first/last seen + confidence)
  ├─ Every URL (defang + first/last seen + confidence)
  ├─ Every hash (MD5/SHA1/SHA256)
  ├─ Every email
  ├─ Every mutex
  ├─ Every registry key
  ├─ Every file path
  ├─ Every named pipe
  ├─ Every crypto wallet
  └─ Deduplicated + sorted by confidence

MITRE ATT&CK (deep)
  ├─ Every technique
  ├─ Technique ID + name + tactic
  ├─ Evidence per technique
  ├─ Confidence per technique
  └─ Sub-techniques

RISK SCORE (explainable)
  ├─ Score: 0-100
  ├─ Verdict
  ├─ Confidence
  ├─ Every signal with weight + contribution
  ├─ Top contributing signals
  ├─ Counter-signals
  └─ Explanation paragraph

SIMILARITY & CLUSTERING
  ├─ ssdeep similarity
  ├─ TLSH similarity
  ├─ imphash neighbors
  ├─ Section-hash neighbors
  ├─ String-set similarity
  ├─ Code similarity
  ├─ Cluster ID
  └─ Family attribution with confidence

SANDBOX (deep, optional)
  ├─ Every process spawned
  ├─ Every file touched
  ├─ Every registry key touched
  ├─ Every network connection
  ├─ Every DNS query
  ├─ Every HTTP request/response
  ├─ Every TLS session
  ├─ Every mutex created
  ├─ Every service installed
  ├─ Every scheduled task created
  ├─ Every screenshot
  ├─ Memory dumps with secrets
  ├─ Anti-VM / anti-debug events
  └─ Multi-stage payload follow-up

REPORT (deep)
  ├─ All sections populated
  ├─ Raw evidence appendix
  ├─ 30+ export formats
  └─ Self-verification passed

---

## 2.4 — DOMAIN ANALYST (Deep)

```

svgsvg
DOMAIN OVERVIEW
├─ Domain name
├─ FQDN
├─ Registered domain
├─ Subdomain depth
├─ Length
├─ Entropy
├─ Punycode decode
├─ IDN homoglyph check
├─ Mixed-script check
├─ Typosquatting check (Levenshtein, keyboard-adjacent, homophone,
│ bitsquatting, vowel-swap, TLD-swap, hyphenation, plural, omission)
├─ Lookalike brand matches (top 20)
└─ Verdict
WHOIS / RDAP (deep)
├─ Registrar
├─ Registrar URL
├─ Registrar IANA ID
├─ WHOIS server
├─ Creation date
├─ Updated date
├─ Expiration date
├─ Domain age (days)
├─ Registrant name / org / email / phone / address (if public)
├─ Admin contact
├─ Tech contact
├─ Name servers (every one with IP)
├─ DNSSEC status
├─ Status codes (clientTransferProhibited, etc.)
├─ Privacy protection (yes/no + provider)
├─ Historical WHOIS changes (every change with date)
└─ Verdict
DNS RECORDS (deep)
For EVERY record type:
├─ A (every IP with TTL + first/last seen)
├─ AAAA (every IP with TTL + first/last seen)
├─ CNAME (every target)
├─ MX (every server with priority + IP)
├─ NS (every server with IP)
├─ TXT (every value — SPF, DKIM, DMARC, verification, etc.)
├─ SOA (every field)
├─ PTR (every reverse)
├─ SRV (every service)
├─ CAA (every issuer)
├─ NAPTR
├─ DNSKEY / DS / RRSIG (DNSSEC)
├─ TLSA
├─ SSHFP
├─ HINFO
└─ ANY (if allowed)
DNS SECURITY (deep)
├─ DNSSEC validation
├─ DNSKEY presence
├─ DS record at parent
├─ RRSIG signatures
├─ NSEC / NSEC3 records
├─ Chain of trust validation
├─ Zone walking possible
└─ Verdict
PASSIVE DNS (deep)
├─ Every historical A record (with first/last seen)
├─ Every historical AAAA record
├─ Every historical MX record
├─ Every historical NS record
├─ Every historical TXT record
├─ Every IP ever associated
├─ Timeline of changes
├─ Fast-flux detection
├─ IP rotation patterns
└─ Verdict
SUBDOMAINS (deep)
├─ Every subdomain discovered (crt.sh, passive DNS, brute-force)
├─ Every subdomain with A record
├─ Every subdomain with response code
├─ Every subdomain with title
├─ Every subdomain with screenshot (if resolvable)
├─ Wildcard detection
├─ Subdomain takeover risk
└─ Verdict per subdomain
CERTIFICATE TRANSPARENCY (deep)
├─ Every certificate ever issued
├─ Every SAN
├─ Every issuer
├─ Every validity window
├─ Every CT log entry
├─ Every related domain (via SAN)
└─ Verdict
IP ASSOCIATIONS
├─ Every IP ever associated
├─ Every IP with ASN
├─ Every IP with geolocation
├─ Every IP with hosting provider
├─ Every IP with reverse DNS
├─ Every IP with open ports
├─ Reverse IP neighbors (up to 100)
└─ Verdict
CERTIFICATE ASSOCIATIONS
├─ Every certificate ever issued
├─ Every certificate issuer
├─ Every certificate SAN
├─ Shared certificate neighbors (up to 100)
└─ Verdict
RELATED DOMAINS
├─ Same registrant
├─ Same nameservers
├─ Same MX
├─ Same IP
├─ Same certificate
├─ Same favicon
├─ Same analytics ID
├─ Same Google AdSense ID
├─ Same Cloudflare account
└─ Verdict
REPUTATION (deep)
├─ VirusTotal domain report
├─ [URLScan.io](https://urlscan.io/) reports
├─ Google Safe Browsing
├─ Microsoft SmartScreen
├─ PhishTank
├─ OpenPhish
├─ URLhaus
├─ Spamhaus
├─ Cisco Talos
├─ AlienVault OTX
├─ IPQualityScore
├─ GreyNoise
├─ MISP (internal)
├─ OpenCTI (internal)
└─ Aggregate verdict
BRAND / TYPOSQUATTING
├─ Every brand match
├─ Levenshtein distance
├─ Homoglyph analysis
├─ Mixed-script analysis
├─ Hyphenation pattern
├─ TLD swap
├─ Vowel swap
├─ Bit-squatting
├─ Plural/singular
├─ Omission/insertion
└─ Verdict per match
IOC EXTRACTION
├─ Every IP
├─ Every subdomain
├─ Every URL
├─ Every email
├─ Every certificate hash
├─ Every favicon hash
└─ Deduplicated + sorted
MITRE ATT&CK
├─ T1583.001 Acquire Infrastructure: Domains
├─ T1585.002 Establish Accounts: Email Accounts
├─ T1071.001 Application Layer Protocol: Web Protocols
├─ T1071.004 Application Layer Protocol: DNS
└─ Every applicable technique with evidence
RISK SCORE
├─ Score 0-100
├─ Verdict
├─ Confidence
├─ Every signal with weight + contribution
└─ Explanation
REPORT
├─ All sections
├─ Raw evidence appendix
├─ 30+ export formats
└─ Self-verification passed
text

```
---

## 2.5 — IP ANALYST (Deep)

```

svgsvg
IP OVERVIEW
├─ IP address (v4 or v6)
├─ IP range (CIDR)
├─ IP type (public, private, reserved, multicast, loopback, etc.)
├─ Reverse DNS (PTR)
└─ Verdict
GEOLOCATION (deep)
├─ Country (name + code)
├─ Region / state
├─ City
├─ Postal code
├─ Latitude / longitude
├─ Timezone
├─ Accuracy radius
├─ Multiple source comparison (MaxMind, IP2Location, DB-IP)
└─ Verdict
ASN (deep)
├─ ASN number
├─ ASN name
├─ ASN country
├─ ASN organization
├─ ASN reputation
├─ ASN malicious ratio
├─ ASN type (hosting, ISP, education, government, business)
├─ ASN peers
└─ Verdict
HOSTING (deep)
├─ Hosting provider
├─ Hosting type (cloud, VPS, dedicated, shared, bulletproof)
├─ Bulletproof hosting score
├─ Abuse contact
├─ Abuse email
├─ Reporting history
└─ Verdict
REVERSE DNS
├─ PTR record
├─ Forward confirmation
├─ Mismatch check
└─ Verdict
OPEN SERVICES (deep, via Shodan/Censys)
├─ Every open port
├─ Every service banner
├─ Every service version
├─ Every SSL cert
├─ Every technology
└─ Verdict
PORTS (deep)
├─ Every open port
├─ Every filtered port
├─ Every closed port
├─ Port scan history
└─ Verdict
REPUTATION (deep)
├─ AbuseIPDB (score, reports, last report)
├─ IPQualityScore (risk score, fraud score)
├─ GreyNoise (classification, last seen)
├─ VirusTotal (detections)
├─ Spamhaus (blocklist status)
├─ SORBS
├─ Barracuda
├─ CINS
├─ UCEPROTECT
└─ Aggregate verdict
ABUSE REPORTS (deep)
├─ Every report (source, date, category, comment)
├─ Report trends (timeline)
├─ Reporting organizations
└─ Verdict
RELATED DOMAINS (deep)
├─ Every domain ever pointing to this IP
├─ Every domain with same ASN
├─ Passive DNS history
├─ First/last seen per domain
└─ Verdict
RELATED CERTIFICATES
├─ Every certificate issued for this IP
├─ Every certificate with this IP as SAN
├─ Certificate issues
└─ Verdict
HISTORICAL ACTIVITY
├─ First seen
├─ Last seen
├─ Historical ASN
├─ Historical geolocation
├─ Historical reputation
├─ Traffic patterns
└─ Verdict
IOC CORRELATION
├─ Every IOC associated with this IP
├─ Every report referencing this IP
├─ Every campaign using this IP
├─ Every actor using this IP
└─ Verdict
MITRE ATT&CK
├─ Every technique associated with this IP's activity
└─ Verdict
RISK SCORE
├─ Score 0-100
├─ Verdict
├─ Confidence
├─ Every signal with weight + contribution
└─ Explanation
REPORT
├─ All sections
├─ Raw evidence appendix
├─ 30+ export formats
└─ Self-verification passed
text

```
---

## 2.6 — PCAP ANALYST (Deep)

(Full spec was provided earlier. Key additions:)

CAPTURE METADATA (deep)
  ├─ File format (pcap, pcapng, cap, snoop, 5views)
  ├─ Interface list (every one)
  ├─ Snap length
  ├─ Link type
  ├─ First packet timestamp (raw + UTC)
  ├─ Last packet timestamp (raw + UTC)
  ├─ Duration
  ├─ Total packets
  ├─ Total bytes
  ├─ Average packet size
  ├─ Packet size histogram (per size bucket: 0-64, 65-128, ..., 1500+)
  ├─ Capture comment (if any)
  ├─ OS (if in pcapng)
  ├─ Application (if in pcapng)
  └─ Verdict

PROTOCOL HIERARCHY (deep)
  For EVERY protocol:
  ├─ Packet count
  ├─ Byte count
  ├─ Percentage
  ├─ Sub-protocols
  ├─ Anomalies
  └─ Verdict

CONVERSATIONS (deep)
  For EVERY 5-tuple:
  ├─ Src IP + port
  ├─ Dst IP + port
  ├─ Protocol
  ├─ Packet count (each direction)
  ├─ Byte count (each direction)
  ├─ First packet
  ├─ Last packet
  ├─ Duration
  ├─ Packets/second
  ├─ Bytes/second
  ├─ TCP flags summary
  ├─ State
  ├─ Suspicion score
  └─ Verdict

ENDPOINTS (deep)
  For EVERY IP:
  ├─ IP
  ├─ Packets sent
  ├─ Packets received
  ├─ Bytes sent
  ├─ Bytes received
  ├─ Geolocation
  ├─ ASN
  ├─ WHOIS org
  ├─ Reverse DNS
  ├─ Reputation
  ├─ Suspicion
  └─ Verdict

DNS (deep) — every query with 15+ fields (already listed)
HTTP (deep) — every request/response with 20+ fields (already listed)
TLS (deep) — every session with 30+ fields (already listed)
TCP (deep) — every stream with 15+ fields (already listed)
FILE CARVING — every carved file with type-specific extraction
BEACONING DETECTION — every beacon with 15+ fields
DGA DETECTION — every DGA candidate with 10+ fields
DNS TUNNELING — every tunnel with 12+ fields
LATERAL MOVEMENT — every lateral movement with 10+ fields
CREDENTIAL EXTRACTION — every credential with 12+ fields (redacted)
FINGERPRINTS — JA3, JA3S, JA4, JA4S, JA4H, JA4X, HASSH, HASSHServer, p0f
NETWORK GRAPH — force-directed graph with nodes + edges
TIMELINE — every event
MITRE ATT&CK — every technique at PCAP level
RISK SCORE — explainable
REPORT — all sections + raw evidence appendix

---

## 2.7 — MALWARE ANALYST (Deep)

(Full spec was provided earlier. Key additions:)

SAMPLE IDENTIFICATION (deep)
  ├─ Sample filename
  ├─ Sample size
  ├─ Sample type
  ├─ Every hash
  ├─ Fuzzy hashes
  ├─ First seen
  ├─ Last seen
  └─ Verdict

HASH INTELLIGENCE (deep)
  For every hash:
  ├─ VirusTotal (every engine)
  ├─ MalwareBazaar
  ├─ ThreatFox
  ├─ Hybrid Analysis
  ├─ Joe Sandbox
  ├─ ANY.RUN
  ├─ Triage
  ├─ Internal cache
  └─ Verdict

STATIC ANALYSIS (deep)
  ├─ PE / ELF / Mach-O parsing (every field)
  ├─ Strings (ASCII + Unicode + stack + tight + FLOSS)
  ├─ Imports (every one with MITRE)
  ├─ Exports (every one)
  ├─ Sections (every one with entropy + hash)
  ├─ Resources (every one extracted)
  ├─ Entropy (whole + per section + per chunk)
  ├─ Packer detection
  ├─ Compiler detection
  ├─ Language detection
  ├─ Timestamps
  ├─ Debug symbols
  └─ Verdict

REVERSE ENGINEERING (deep)
  ├─ Disassembly (every function)
  ├─ Function graph
  ├─ Call graph
  ├─ Cross-references
  ├─ String references
  ├─ Crypto constant detection (S-boxes, Rcon, IVs)
  ├─ Shellcode detection
  ├─ Obfuscation detection
  └─ Verdict

YARA (deep) — every match with 10+ fields
CONFIGURATION EXTRACTION (deep) — every field
BEHAVIORAL ANALYSIS (deep, from sandbox) — every event
NETWORK ANALYSIS (deep, from sandbox) — every connection
C2 DETECTION (deep) — pattern matching + ML
IOC EXTRACTION (deep)
THREAT INTELLIGENCE (deep)
MITRE ATT&CK (deep)
MALWARE FAMILY (deep) — identification with confidence
CAMPAIGN CORRELATION (deep) — via Neo4j graph
REPORT (deep)

---

## 2.8 — RANSOMWARE ANALYST (Deep)

```

svgsvg
SAMPLE ANALYSIS
├─ Sample identification
├─ Hashes
├─ File type
├─ Packer
├─ Compiler
├─ First seen
├─ Family guess
└─ Verdict
RANSOM NOTE ANALYSIS (deep)
├─ Every ransom note extracted
├─ Every ransom note decoded
├─ Every ransom note hashed
├─ Language
├─ Every payment address (BTC, XMR, etc.)
├─ Every email address
├─ Every TOX ID
├─ Every onion URL
├─ Every Telegram handle
├─ Every deadline
├─ Every threat (leak, DDoS, etc.)
├─ Every victim-specific data
├─ Family attribution
└─ Verdict
EXTENSION ANALYSIS
├─ Every file extension appended
├─ Extension length
├─ Extension entropy
├─ Extension pattern
├─ Family match
└─ Verdict
ENCRYPTION BEHAVIOR (deep)
├─ Crypto algorithm (AES, ChaCha20, RSA, ECC)
├─ Key size
├─ IV / nonce
├─ Key generation method
├─ Key storage (in memory, in file, in registry)
├─ File targeting (every extension)
├─ File size thresholds
├─ Partial encryption (header-only, footer-only, full)
├─ Ransom note drop location
├─ Encryption speed
└─ Verdict
FILE TARGETING (deep)
├─ Every targeted extension (documents, images, databases, etc.)
├─ Every targeted folder
├─ Every excluded folder (system, backup)
├─ Every excluded extension
├─ Network share targeting
├─ Cloud storage targeting
└─ Verdict
PROCESS BEHAVIOR (deep)
├─ Every process spawned
├─ Every command line
├─ Every parent-child relationship
├─ Self-deletion
├─ Process hollowing
├─ Code injection
├─ Token manipulation
└─ Verdict
PERSISTENCE (deep)
├─ Every registry key modified
├─ Every scheduled task created
├─ Every service installed
├─ Every startup folder entry
├─ Every WMI event subscription
├─ Every COM hijack
└─ Verdict
SHADOW COPY ACTIVITY (deep)
├─ vssadmin delete shadows
├─ wbadmin delete catalog
├─ bcdedit /set recoveryenabled No
├─ wmic shadowcopy delete
├─ Every command with full path
├─ Every command with full arguments
└─ Verdict
BACKUP DESTRUCTION (deep)
├─ Every backup service stopped
├─ Every backup service deleted
├─ Every backup file deleted
├─ Every backup share accessed
└─ Verdict
C2 INFRASTRUCTURE (deep)
├─ Every C2 server (Tor, I2P, clearnet, Telegram)
├─ Every C2 protocol
├─ Every C2 encryption
├─ Every C2 fallback
├─ Every C2 config
└─ Verdict
IOC EXTRACTION (deep)
├─ Every IP
├─ Every domain
├─ Every URL
├─ Every hash
├─ Every email
├─ Every crypto wallet
├─ Every extension
├─ Every mutex
├─ Every registry key
└─ Verdict
RANSOMWARE FAMILY (deep)
├─ Family identification
├─ Family confidence
├─ Family variant
├─ Family version
├─ Family signature
├─ Family known tools
└─ Verdict
THREAT ACTOR / CAMPAIGN (deep)
├─ Actor attribution
├─ Actor confidence
├─ Campaign attribution
├─ Campaign confidence
├─ Prior victims
├─ Prior IOCs
└─ Verdict
MITRE ATT&CK (deep)
├─ Every technique
├─ Every technique with evidence
└─ Verdict
KILL CHAIN (deep)
├─ Reconnaissance
├─ Weaponization
├─ Delivery
├─ Exploitation
├─ Installation
├─ Command & Control
├─ Actions on Objectives
└─ Every stage with evidence
IMPACT ASSESSMENT (deep)
├─ Estimated blast radius (files, folders, shares)
├─ Estimated downtime
├─ Estimated data loss
├─ Estimated recovery cost
├─ Regulatory impact
├─ Reputational impact
└─ Verdict
EVIDENCE (deep)
├─ Every ransom note
├─ Every encrypted file sample
├─ Every registry export
├─ Every scheduled task XML
├─ Every process dump
├─ Every memory dump
├─ Every network capture
└─ Verdict
TIMELINE (deep)
├─ First file encrypted
├─ Last file encrypted
├─ Ransom note dropped
├─ Persistence established
├─ C2 contacted
├─ Backup destroyed
└─ Every event with timestamp
INCIDENT REPORT (deep)
├─ Executive summary
├─ Technical findings
├─ Impact assessment
├─ Recommendations
├─ Raw evidence appendix
├─ 30+ export formats
└─ Self-verification passed
text

```
---

## 2.9 — IOC ANALYST (Deep)

```

svgsvg
IOC OVERVIEW
├─ IOC value
├─ IOC type (IP, domain, URL, hash, email, certificate, wallet)
├─ Defanged value
├─ Normalized value
├─ First seen
├─ Last seen
├─ Source(s)
└─ Verdict
IOC ENRICHMENT (deep)
For every IOC:
├─ VirusTotal (every engine + result + date)
├─ [URLScan.io](https://urlscan.io/)
├─ Google Safe Browsing
├─ Microsoft SmartScreen
├─ PhishTank
├─ OpenPhish
├─ URLhaus
├─ Spamhaus
├─ AlienVault OTX
├─ AbuseIPDB
├─ IPQualityScore
├─ GreyNoise
├─ MISP (internal)
├─ OpenCTI (internal)
├─ WHOIS / RDAP
├─ DNS records
├─ Passive DNS
├─ SSL certificate
├─ ASN
├─ Geolocation
└─ Aggregate verdict
IOC CORRELATION (deep)
├─ Every related IOC
├─ Every shared infrastructure
├─ Every shared certificate
├─ Every shared favicon
├─ Every shared ASN
├─ Every shared nameserver
├─ Every shared registrant
├─ Graph visualization
└─ Verdict
CONFIDENCE (deep)
├─ Per-source confidence
├─ Aggregate confidence
├─ Confidence breakdown
└─ Verdict
REPUTATION (deep)
├─ Aggregate reputation score
├─ Per-source reputation
├─ Reputation trend over time
└─ Verdict
FIRST SEEN / LAST SEEN (deep)
├─ First seen per source
├─ Last seen per source
├─ First seen globally
├─ Last seen globally
├─ Timeline chart
└─ Verdict
RELATED INFRASTRUCTURE (deep)
├─ Every related IP
├─ Every related domain
├─ Every related URL
├─ Every related hash
├─ Every related certificate
├─ Every related favicon
├─ Every related ASN
├─ Every related nameserver
├─ Every related registrant
└─ Graph visualization
IOC EXPORT (deep)
├─ STIX 2.1 bundle
├─ MISP event
├─ OpenIOC
├─ MAEC
├─ CSV
├─ JSON
├─ YAML
├─ FireEye IOC
└─ Every format
MITRE ATT&CK (deep)
├─ Every technique associated with this IOC
└─ Verdict
REPORT (deep)
├─ All sections
├─ Raw evidence appendix
├─ 30+ export formats
└─ Self-verification passed
text

```
---

## 2.10 — PHISHING KIT ANALYST (Deep)

```

svgsvg
KIT IDENTIFICATION (deep)
├─ Kit name (if known)
├─ Kit version
├─ Kit family (16Shop, Monkey, LogoKit, Caffeine, XBAP, etc.)
├─ Kit fingerprint (HTML structure, JS structure, file paths)
├─ Kit confidence
├─ Kit source (if available on GitHub/pastebin)
└─ Verdict
HTML ANALYSIS (deep)
├─ Full raw HTML
├─ Sanitized HTML
├─ Every tag
├─ Every form
├─ Every input
├─ Every hidden field
├─ Every CSS rule (hidden text, offscreen, tiny fonts)
├─ Every JavaScript reference
├─ Every external resource
├─ Obfuscation techniques
└─ Verdict
JAVASCRIPT ANALYSIS (deep)
├─ Full AST
├─ Every eval / Function / setTimeout / setInterval
├─ Every obfuscation layer peeled
├─ Every network call
├─ Every DOM manipulation
├─ Every crypto operation
├─ Every form grab
├─ Every keyboard event listener
├─ Every clipboard operation
├─ Detected kit behavior
└─ Verdict
CREDENTIAL FORM DETECTION (deep)
├─ Every form
├─ Action URL
├─ Method
├─ Every field (name, type, placeholder, required, pattern)
├─ Password fields
├─ Email fields
├─ OTP fields
├─ Credit card fields
├─ Hidden fields (with values)
├─ Multi-step form detection
├─ Form validation rules
├─ Where the form submits (attacker panel)
└─ Verdict
BRAND DETECTION (deep)
├─ Every brand matched
├─ SSIM score
├─ Favicon mmh3
├─ Logo detection
├─ Title match
├─ Copyright text match
├─ Layout similarity
├─ Color palette similarity
├─ Wording similarity
└─ Verdict
OBFUSCATION DETECTION (deep)
├─ HTML entities
├─ JS escapes
├─ Base64
├─ ROT13
├─ XOR
├─ Unicode escapes
├─ String array rotation
├─ Dead code injection
├─ Anti-debug
├─ Anti-VM
└─ Verdict
IOC EXTRACTION (deep)
├─ Every URL (defanged)
├─ Every domain (defanged)
├─ Every IP (defanged)
├─ Every email
├─ Every Telegram bot token
├─ Every Discord webhook
├─ Every Slack webhook
├─ Every Bitcoin wallet
├─ Every panel URL
├─ Every exfil endpoint
└─ Verdict
INFRASTRUCTURE MAPPING (deep)
├─ Every server
├─ Every CDN
├─ Every panel URL
├─ Every exfil endpoint
├─ Every redirect chain
├─ Every SSL certificate
├─ Every ASN
├─ Every geolocation
└─ Verdict
CAMPAIGN CORRELATION (deep)
├─ Every related campaign
├─ Every related actor
├─ Every shared IOC
├─ Every shared infrastructure
├─ Graph visualization
└─ Verdict
MITRE ATT&CK (deep)
├─ T1566.002 Spearphishing Link
├─ T1204.001 User Execution: Malicious Link
├─ T1583.001 Acquire Infrastructure: Domains
├─ T1585.002 Establish Accounts: Email Accounts
├─ T1071.001 Application Layer Protocol: Web Protocols
└─ Every applicable technique with evidence
RISK SCORE
├─ Score 0-100
├─ Verdict
├─ Confidence
├─ Every signal with weight + contribution
└─ Explanation
REPORT (deep)
├─ All sections
├─ Raw evidence appendix
├─ 30+ export formats
└─ Self-verification passed
text

```
---

## 2.11 — THREAT INTELLIGENCE (Deep)

```

svgsvg
THREAT INTEL OVERVIEW
├─ Total IOCs tracked
├─ Total campaigns
├─ Total actors
├─ Total feeds
├─ Total sources
└─ Verdict
IOC CORRELATION (deep)
├─ Every IOC
├─ Every related IOC
├─ Every relationship type
├─ Every confidence level
├─ Graph visualization
└─ Verdict
MALWARE (deep)
├─ Every malware family
├─ Every family with IOCs
├─ Every family with TTPs
├─ Every family with campaign
├─ Every family with actor
└─ Verdict per family
CAMPAIGN TRACKING (deep)
├─ Every campaign
├─ Every campaign with IOCs
├─ Every campaign with TTPs
├─ Every campaign with actor
├─ Every campaign timeline
├─ Every campaign victim
└─ Verdict per campaign
THREAT ACTOR (deep)
├─ Every actor
├─ Every actor with aliases
├─ Every actor with TTPs
├─ Every actor with campaigns
├─ Every actor with IOCs
├─ Every actor with targets
├─ Every actor with attribution confidence
└─ Verdict per actor
RELATIONSHIP GRAPH (deep)
├─ Every entity (IOC, campaign, actor, malware, TTP)
├─ Every relationship
├─ Every relationship confidence
├─ Every relationship source
├─ Interactive graph (Cytoscape)
└─ Verdict
FEED INGESTION (deep)
├─ Every feed (PhishTank, OpenPhish, URLhaus, etc.)
├─ Every feed with update frequency
├─ Every feed with record count
├─ Every feed with last update
├─ Every feed with new records (delta)
├─ Every feed with reputation
└─ Verdict per feed
INTEGRATION (deep)
├─ Push to MISP
├─ Push to OpenCTI
├─ Push to SIEM (Splunk, Sentinel, QRadar)
├─ Push to SOAR (Cortex XSOAR, Tines, Torq)
├─ Push to ticketing (Jira, ServiceNow)
├─ Every push with status + timestamp
└─ Verdict
REPORT (deep)
├─ All sections
├─ Raw evidence appendix
├─ 30+ export formats
└─ Self-verification passed
text

```
---

## 2.12 — SANDBOX (Deep)

```

svgsvg
SANDBOX OVERVIEW
├─ Sandbox name (CAPEv2, ANY.RUN, Joe, Hybrid, VMRay, Triage)
├─ Task ID
├─ Status
├─ Queue position
├─ Estimated time
└─ Verdict
SUBMISSION (deep)
├─ Sample (file or URL)
├─ Options (timeout, machine, network, etc.)
├─ Submission timestamp
├─ Submission response
└─ Verdict
EXECUTION (deep)
├─ Every process spawned (name, PID, PPID, cmdline, integrity)
├─ Every file touched (create/write/delete + path + hash)
├─ Every registry key touched
├─ Every network connection (IP, port, protocol, bytes)
├─ Every DNS query
├─ Every HTTP request/response
├─ Every TLS session
├─ Every mutex created
├─ Every service installed
├─ Every scheduled task created
├─ Every screenshot (with timestamp)
├─ Every memory dump with secrets
├─ Anti-VM / anti-debug events
└─ Verdict per event
NETWORK CAPTURE (deep)
├─ Full PCAP (linked to PCAP ANALYST)
├─ Every connection
├─ Every DNS query
├─ Every HTTP request
├─ Every TLS session
├─ Every C2 callback
└─ Verdict
CONFIG EXTRACTION (deep)
├─ Every family-specific config
├─ Every C2 server
├─ Every encryption key
├─ Every bot token
├─ Every campaign ID
└─ Verdict
ANTI-EVASION (deep)
├─ Anti-VM checks (VMware, VirtualBox, Hyper-V, QEMU)
├─ Anti-debug checks
├─ Anti-sandbox checks
├─ Timing checks
├─ Sleep skipping
├─ Multi-round detonation
└─ Verdict per technique
MULTI-STAGE FOLLOW-UP (deep)
├─ Every dropped file re-analyzed
├─ Every C2 payload downloaded
├─ Every lateral movement
└─ Verdict
IOC EXTRACTION (deep)
├─ Every IP
├─ Every domain
├─ Every URL
├─ Every hash
├─ Every mutex
├─ Every registry key
├─ Every file path
├─ Every wallet
└─ Verdict
MITRE ATT&CK (deep)
├─ Every technique observed
├─ Every technique with evidence
└─ Verdict
REPORT (deep)
├─ All sections
├─ Raw evidence appendix
├─ 30+ export formats
└─ Self-verification passed
text

```
---

## 2.13 — REPORTS (Deep)

```

svgsvg
REPORT OVERVIEW
├─ Report ID
├─ Report type (technical, executive, compliance, etc.)
├─ Report version
├─ Report hash (SHA256)
├─ Generated at
├─ Generated by
├─ Reviewed by
├─ Status (draft, final, signed)
└─ Verdict
REPORT CONTENT (deep)
├─ Cover page
├─ Classification banner
├─ Table of contents
├─ Executive summary (AI + human-editable)
├─ Verdict + risk score
├─ Key findings
├─ MITRE ATT&CK summary
├─ Timeline
├─ IOC table
├─ URL analysis section
├─ Email analysis section
├─ File analysis section
├─ Domain analysis section
├─ IP analysis section
├─ PCAP analysis section
├─ Malware analysis section
├─ Ransomware analysis section
├─ IOC analysis section
├─ Phishing kit analysis section
├─ Threat intelligence section
├─ Sandbox section
├─ Correlation section
├─ Recommendations
├─ Appendix A: Raw headers
├─ Appendix B: Raw JSON
├─ Appendix C: YARA rules
├─ Appendix D: Detection rules
├─ Appendix E: Blocklists
├─ Appendix F: Glossary
├─ Appendix G: References
├─ Appendix H: Report metadata
└─ Signature block
REPORT EXPORTS (deep)
├─ HTML (self-contained)
├─ HTML (print)
├─ HTML (public)
├─ HTML (widget)
├─ PDF (WeasyPrint)
├─ PDF/A
├─ DOCX
├─ XLSX
├─ PPTX
├─ Markdown
├─ Plain text
├─ RTF
├─ ODT
├─ EPUB
├─ JSON
├─ JSON (minified)
├─ JSON-LD
├─ XML
├─ YAML
├─ CSV
├─ TSV
├─ Parquet
├─ Avro
├─ STIX 2.1
├─ STIX JSON
├─ STIX XML
├─ TAXII
├─ MISP event
├─ MISP attribute
├─ OpenIOC
├─ CybOX
├─ MAEC
├─ VERIS
├─ FireEye IOC
├─ YARA
├─ Sigma
├─ Suricata
├─ Snort
├─ Zeek
├─ KQL
├─ SPL
├─ AQL
├─ EQL
├─ Sigma correlation
├─ Blocklist iptables
├─ Blocklist nftables
├─ Blocklist pfSense
├─ Blocklist Palo Alto
├─ Blocklist Fortinet
├─ Blocklist Cisco ASA
├─ Blocklist Check Point
├─ Blocklist BIND
├─ Blocklist Unbound
├─ Blocklist Pi-hole
├─ Blocklist AdGuard
├─ Blocklist Squid
├─ Blocklist Bluecoat
├─ Blocklist Zscaler
├─ Blocklist Cloudflare
├─ Blocklist AWS WAF
├─ Blocklist Azure WAF
├─ Blocklist Windows
├─ Blocklist macOS
├─ GraphML
├─ GEXF
├─ DOT
├─ Mermaid
├─ SVG
├─ PNG
├─ MITRE Navigator layer
├─ MITRE D3FEND
├─ Kill Chain
├─ Diamond Model
├─ SARIF
├─ CycloneDX
├─ SPDX
├─ OpenAPI
├─ Postman Collection
├─ Jupyter Notebook
├─ R Markdown
├─ LaTeX
├─ BibTeX
├─ Email HTML
├─ Email text
├─ Slack Block Kit
├─ Teams Adaptive Card
├─ Discord Embed
├─ Telegram Markdown
├─ Webhook JSON
└─ ZIP bundle
REPORT FEATURES (deep)
├─ White-label branding
├─ Multi-language (en, fr, es, ar, zh)
├─ Executive + technical audiences
├─ Editable DOCX
├─ Presentable PPTX
├─ Analyzable XLSX
├─ Shareable public link (expiry + password)
├─ Embeddable HTML widget
├─ Comparable (diff two reports)
├─ Scheduled delivery
├─ Versioned
├─ Hashable
├─ Signable (GPG, X.509)
├─ Watermarkable
├─ Redactable
├─ Searchable
├─ Annotatable
├─ Exportable as ZIP
├─ API-accessible
├─ Webhook-delivered
├─ Compliance-ready (SOC 2, ISO 27001, PCI, HIPAA, GDPR)
└─ Guest-accessible (with guest footer)
REPORT API (deep)
├─ 30+ endpoints (one per format)
├─ Regenerate endpoint
├─ Sign endpoint
├─ Watermark endpoint
├─ Redact endpoint
├─ Share endpoint
├─ Schedule endpoint
├─ Compare endpoint
├─ Annotate endpoint
└─ Every endpoint documented
REPORT STORAGE (deep)
├─ S3/MinIO per-tenant prefix
├─ Postgres metadata
├─ Elasticsearch full-text index
├─ Signed URLs (expiry 1h)
├─ Retention policy per tier
├─ Automatic cleanup of old versions
└─ Verdict
REPORT VERIFICATION (deep)
├─ SHA256 hash
├─ Digital signature (if signed)
├─ Timestamp
├─ Chain of custody
└─ Verdict
text

```
---

## 2.14 — CASES (Deep)

```

svgsvg
CASE OVERVIEW
├─ Case ID
├─ Case title
├─ Case description
├─ Case status (new, triage, investigating, contained, closed, FP)
├─ Priority (P1-P4)
├─ Severity (critical, high, medium, low, info)
├─ SLA deadline
├─ Assignee
├─ Watchers
├─ Tags
├─ Custom fields
├─ Created at
├─ Updated at
└─ Verdict
CASE EVIDENCE (deep)
├─ Every linked scan
├─ Every linked report
├─ Every linked IOC
├─ Every linked file
├─ Every linked email
├─ Every linked URL
├─ Every linked PCAP
├─ Every linked sandbox run
├─ Chain of custody
├─ Immutable audit log
└─ Verdict
CASE TIMELINE (deep)
├─ Every event chronologically
├─ Every action by every user
├─ Every state change
├─ Every comment
├─ Every attachment
└─ Verdict
CASE COLLABORATION (deep)
├─ Every comment (threaded)
├─ Every @mention
├─ Every attachment
├─ Every watcher
├─ Every notification
└─ Verdict
CASE WORKFLOW (deep)
├─ Kanban board
├─ List view
├─ Calendar view
├─ Bulk actions
├─ Templates (phishing, malware, BEC)
├─ Playbooks (automated steps)
└─ Verdict
CASE REPORTING (deep)
├─ Case summary
├─ Timeline
├─ IOCs
├─ Recommendations
├─ Export PDF
├─ Export DOCX
├─ Export STIX
├─ Send to SIEM/SOAR
└─ Verdict
CASE METRICS (deep)
├─ MTTD (mean time to detect)
├─ MTTR (mean time to respond)
├─ MTTA (mean time to acknowledge)
├─ Analyst productivity
├─ SLA compliance
├─ False positive rate
└─ Verdict
text

```
---

## 2.15 — CAMPAIGNS (Deep)

```

svgsvg
CAMPAIGN OVERVIEW
├─ Campaign ID
├─ Campaign name
├─ Campaign description
├─ Campaign type (phishing, malware, ransomware, BEC, etc.)
├─ First seen
├─ Last seen
├─ Status (active, dormant, closed)
├─ Confidence
└─ Verdict
CAMPAIGN IOCs (deep)
├─ Every IP
├─ Every domain
├─ Every URL
├─ Every hash
├─ Every email
├─ Every certificate
├─ Every favicon
├─ Every ASN
├─ Every mutex
├─ Every registry key
└─ Verdict per IOC
CAMPAIGN TTPs (deep)
├─ Every MITRE technique
├─ Every technique with evidence
├─ Every tool
├─ Every infrastructure pattern
└─ Verdict
CAMPAIGN VICTIMS (deep)
├─ Every victim (if available)
├─ Every victim sector
├─ Every victim country
├─ Every victim size
└─ Verdict
CAMPAIGN TIMELINE (deep)
├─ Every event chronologically
├─ Every evolution
├─ Every infrastructure change
└─ Verdict
CAMPAIGN ATTRIBUTION (deep)
├─ Actor attribution
├─ Actor confidence
├─ Prior campaigns by same actor
├─ Shared infrastructure
└─ Verdict
CAMPAIGN REPORT (deep)
├─ All sections
├─ Raw evidence appendix
├─ 30+ export formats
└─ Self-verification passed
text

```
---

## 2.16 — ACTORS (Deep)

```

svgsvg
ACTOR OVERVIEW
├─ Actor ID
├─ Actor name
├─ Actor aliases
├─ Actor type (APT, cybercrime, hacktivist, insider, etc.)
├─ Actor country
├─ Actor motivation
├─ Actor sophistication
├─ First seen
├─ Last seen
├─ Status (active, dormant, retired)
└─ Verdict
ACTOR TTPs (deep)
├─ Every MITRE technique
├─ Every technique with evidence
├─ Every tool
├─ Every infrastructure pattern
├─ Every delivery mechanism
└─ Verdict
ACTOR CAMPAIGNS (deep)
├─ Every campaign
├─ Every campaign with timeline
├─ Every campaign with victims
└─ Verdict
ACTOR IOCs (deep)
├─ Every IP
├─ Every domain
├─ Every URL
├─ Every hash
├─ Every certificate
└─ Verdict
ACTOR TARGETS (deep)
├─ Every sector
├─ Every country
├─ Every organization type
├─ Every organization size
└─ Verdict
ACTOR ATTRIBUTION (deep)
├─ Attribution confidence
├─ Attribution evidence
├─ Competing hypotheses
└─ Verdict
ACTOR REPORT (deep)
├─ All sections
├─ Raw evidence appendix
├─ 30+ export formats
└─ Self-verification passed
text

```
---

## 2.17 — IOC GRAPH (Deep)

```

svgsvg
GRAPH OVERVIEW
├─ Total nodes
├─ Total edges
├─ Node types (IOC, campaign, actor, malware, TTP)
├─ Edge types (resolves_to, hosts, redirects_to, drops, contacts,
│ uses, attributed_to, targets, related_to, shares_cert,
│ shares_favicon, shares_ip)
└─ Verdict
GRAPH VISUALIZATION (deep)
├─ Interactive Cytoscape graph
├─ Node size = importance
├─ Node color = verdict
├─ Edge thickness = confidence
├─ Filter by entity type
├─ Filter by confidence
├─ Expand node (load neighbors)
├─ Shortest path between two IOCs
├─ Cluster detection
├─ Community detection
├─ Timeline overlay
└─ Verdict
GRAPH ANALYSIS (deep)
├─ Centrality metrics (degree, betweenness, closeness, eigenvector)
├─ Community detection (Louvain, Leiden)
├─ Clustering coefficient
├─ PageRank
├─ Shortest paths
├─ Connected components
├─ Anomaly detection
└─ Verdict
GRAPH EXPORT (deep)
├─ GraphML
├─ GEXF
├─ DOT
├─ Mermaid
├─ SVG
├─ PNG
├─ JSON
└─ Verdict
GRAPH QUERIES (deep)
├─ Pivot by IOC
├─ Pivot by campaign
├─ Pivot by actor
├─ Pivot by malware family
├─ Pivot by infrastructure
├─ Find all IOCs seen with this IOC
├─ Find all campaigns using this IOC
├─ Find all actors using this IOC
└─ Verdict
text

```
---

## 2.18 — FEEDS (Deep)

```

svgsvg
FEED OVERVIEW
├─ Total feeds
├─ Total records
├─ Last update
├─ Update frequency
└─ Verdict
FEED LIST (deep)
For EVERY feed:
├─ Feed name (PhishTank, OpenPhish, URLhaus, MalwareBazaar, etc.)
├─ Feed type (phishing, malware, ransomware, etc.)
├─ Feed URL
├─ Feed format (JSON, CSV, XML, STIX, TAXII)
├─ Feed authentication
├─ Feed update frequency
├─ Feed last update
├─ Feed record count
├─ Feed new records (delta)
├─ Feed quality score
└─ Verdict per feed
FEED INGESTION (deep)
├─ Every record ingested
├─ Every record deduplicated
├─ Every record enriched
├─ Every record timestamped
├─ Every record with source
└─ Verdict
FEED CORRELATION (deep)
├─ Every record cross-referenced with internal data
├─ Every record linked to campaigns
├─ Every record linked to actors
└─ Verdict
FEED REPORT (deep)
├─ Feed summary
├─ Feed trends
├─ Feed quality
├─ Raw evidence appendix
├─ 30+ export formats
└─ Self-verification passed
text

```
---

# PART 3 — UPDATED FULL CODE STRUCTURE

Add these to the tree from the v3 prompt:

```

svgsvg
cyber_phish_k4/
├── analyzers/
│ ├── email/ # 40+ files
│ ├── url/ # 35+ files
│ ├── file/ # 70+ files
│ ├── domain/ # 15+ files
│ ├── ip/ # 15+ files
│ ├── pcap/ # 70+ files
│ ├── malware/ # 15+ files
│ ├── ransomware/ # 20+ files
│ ├── ioc/ # 10+ files
│ ├── phishing_kit/ # 12+ files
│ ├── threat_intelligence/ # 12+ files
│ └── common/
│ ├── ioc_extract.py
│ ├── defang.py
│ ├── normalize.py
│ ├── validators.py
│ ├── scoring_helpers.py
│ ├── entropy_helpers.py
│ ├── evidence.py # NEW: raw evidence capture
│ ├── mitre_map.py # NEW: MITRE mapping helper
│ ├── confidence.py # NEW: confidence scoring
│ └── timeline.py # NEW: timeline builder
│
├── reports/
│ ├── builder.py
│ ├── renderer.py
│ ├── postprocess.py
│ ├── evidence_appendix.py # NEW: raw evidence appendix builder
│ ├── exporters/ # 100+ files
│ └── templates/
│ ├── base_report.html.j2
│ ├── sections/ # 60+ sections
│ └── styles/
│
├── tasks/
│ ├── email_tasks.py
│ ├── url_tasks.py
│ ├── file_tasks.py
│ ├── domain_tasks.py
│ ├── ip_tasks.py
│ ├── pcap_tasks.py
│ ├── malware_tasks.py
│ ├── ransomware_tasks.py
│ ├── ioc_tasks.py
│ ├── phishing_kit_tasks.py
│ ├── threat_intelligence_tasks.py
│ ├── sandbox_tasks.py
│ ├── enrichment_tasks.py
│ ├── ai_tasks.py
│ ├── report_tasks.py
│ ├── report_export_tasks.py
│ ├── report_schedule_tasks.py
│ ├── notification_tasks.py
│ ├── feed_tasks.py
│ ├── integration_tasks.py
│ ├── status_tasks.py
│ ├── guest_tasks.py
│ └── maintenance_tasks.py
│
├── workers/ # matching worker files for every task
│
├── services/ # matching service files for every analyzer
│
├── models/ # matching models for every analyzer
│
├── schemas/ # matching schemas for every analyzer
│
├── api/v1/ # matching API routes for every analyzer
│
└── web/routes/ # matching web routes for every analyzer