# V20 Module Map

The canonical runtime currently contains hundreds of executable modules. Major areas:

- `ai/` — task planning and evidence-grounded reasoning
- `attack_surface.py` — normalized DNS/infrastructure surface
- `breach/` — breach/exposure boundary
- `certificates/` — certificate reuse
- `connectors/` — provider catalog and connector adapters
- `content/` — HTML/JavaScript surface extraction without target JS execution
- `correlation/` — entity resolution, clustering and graph metrics
- `ct/` — certificate-transparency analysis
- `detection/` — DGA and DNS-tunneling analysis
- `dns/` — DNS, DNSSEC, mail-security and temporal analysis
- `domain/` — anatomy, registration and typosquat analysis
- `evidence/` — evidence ledger and chain summaries
- `geo/` — provider-backed system locations
- `graph/` — relationship graph and layouts
- `http/` — HTTP posture and redirects
- `infrastructure/` — ASN, cloud, hosting and CDN/WAF
- `monitoring/` — drift/watch planning
- `orchestration/` — deep pipeline and collection plan
- `osint/` — public OSINT and search pivots
- `pdns/` — passive-DNS contracts
- `pivots/` — investigation pivot suggestions
- `rdap/` — registration lifecycle
- `reporting/` — case/report schemas
- `reputation/` — reputation fusion
- `scoring/` — explainable risk dimensions/calibration
- `security/` — detections and typo families
- `services/` — service/banner normalization
- `subdomains/` — subdomain discovery contracts
- `technology/` — technology/security-stack analysis
- `tls/` — TLS posture
- `url/` — URL anatomy/encoding/similarity/risk
- `utils/` — normalization, encoding, Unicode and redaction
- `workforce/` — authorized provider workforce observations
- `v20/` — V20 contracts and release metadata
