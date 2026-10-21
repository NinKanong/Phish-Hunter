# Cyber-Phish-k4 22.0.0 — Unified Investigation Backend + Workbench

Cyber-Phish-k4 is a native Python defensive-analysis platform with isolated analyst workspaces for phishing, malware, network evidence, indicators and threat intelligence.

## Analyst workspaces

Version 10.1 adds dedicated guest workflows for every service, a strict JSON-safe result boundary, deeper static phishing-kit/ransomware/IOC/domain/IP analysis, PCAPNG support, feed parsing, report generation, guest case/campaign/actor workspaces and an isolated sandbox submission manifest.

- Email Analyst — MIME/header/authentication/content/URL/attachment/IOC triage.
- URL Analyst — URL parsing, SSRF-aware collection, redirects, headers, forms and risk evidence.
- File Analyst — static file identification, hashes, entropy, strings and suspicious API signals.
- Domain Analyst — DNS resolution, domain structure, IP associations and evidence.
- IP Analyst — IPv4/IPv6 classification, reverse DNS and IOC context.
- PCAP Analyst — authorized PCAP/PCAPNG metadata, IPv4/IPv6 flows, DNS, protocol statistics, suspicious ports and IOC extraction.
- Malware Analyst — static malware triage and intelligence context.
- Ransomware Analyst — defensive artifact and sample triage.
- IOC Analyst — indicator extraction and normalization.
- Phishing Kit Analyst — authorized HTML/JS and credential-form triage.
- Threat Intelligence — connector catalog, enrichment and correlation foundation.
- Sandbox — isolated-provider integration boundary; the web process does not execute uploads.
- Reports, Cases, Campaigns, Threat Actors, IOC Graph and Threat Feeds — operational workspaces.

## Header

The public site follows the requested structure:

`Cyber-Phish-k4 | Services | Blog | About | Resource | Guest mode | Sign in | Sign up`

Services is a three-column mega-menu split into Analyze, Investigate and Operate. Resource contains Learn, Community and Support.

## Guest mode

All service workspaces are accessible without an account. A guest ID is stored in a short-lived secure cookie and guest scans are retained for 24 hours in the local database. When a guest registers, the guest scans and extracted IOCs are migrated into the new tenant.

Guest mode is intended for authorized defensive analysis. It has no API keys, scheduled reports, SSO or white-label features.

## Run locally

Linux/macOS:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements/base.txt
python run.py
```

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements/base.txt
python run.py
```

Open `http://127.0.0.1:8000`.

After signing in, open `http://127.0.0.1:8000/workbench` for the unified investigation workbench. The workbench is connected to the same SQL database, durable evidence storage, job pipeline, IOC registry, case registry and report registry as the main application.

Admin control center:

```powershell
python run.py
```

Open `http://127.0.0.1:8000/admin`.

## Verify

```bash
python -m compileall -q phishhunter libs/py-common
python -m pytest -q
```

For development linting:

```bash
pip install -r requirements/dev.txt
ruff check .
black --check .
```

The packaging environment used for this build had pytest and the runtime dependencies available, but network access was unavailable for installing ruff/black. Therefore compileall and pytest were executed successfully; lint tools are included in `requirements/dev.txt` for the user's environment.

## Security boundary

The local web process does not execute uploaded malware. URL analysis uses an SSRF-aware guard. Sandbox execution is an explicit integration boundary and must be deployed in an isolated analysis environment with appropriate authorization, network controls and secrets.

External threat-intelligence connectors are opt-in and require their provider credentials. The platform does not claim that 1000+ external sources are active until those connectors are configured.

## Packaging

```bash
python make_zip.py
```

This creates `../cyber-phish-k4.zip` from the project tree while excluding caches, virtual environments, databases and compiled bytecode.

## 10.2 deep analyst features

The service workspaces now expose a richer result and reporting layer:

- Live client-side analysis pipeline progress with intake, deep-analysis, correlation and reporting stages.
- Professional result pages with risk, IOC, evidence, finding and ATT&CK metrics.
- PCAP/PCAPNG passive network forensics including IPv4/IPv6, DNS, HTTP metadata, TLS SNI, flows, internal host profiles, potential compromised-host candidates, potential C2 candidates and external-attacker candidates. These are heuristic candidates and must be validated with independent telemetry.
- Report exports: PDF, standalone HTML, JSON, Markdown, STIX 2.1, text, IOC CSV, connection-flow CSV, and a ZIP bundle containing all formats.
- Stronger Blacklight mode with persistent preference and pointer-following analyst glow.
- All 18 service routes have GET workspace pages and executable guest workflows; external TI providers and dynamic sandbox execution remain explicit integration boundaries.

### PCAP assessment model

The PCAP engine does not claim that a host was hacked solely from a capture. It produces evidence-backed candidates such as:

1. internal hosts with unusual outbound public connections,
2. repeated or periodic outbound flows that may resemble C2,
3. external sources repeatedly connecting to internal hosts, and
4. inbound activity on common administration/exposure ports.

Use endpoint telemetry, authentication logs, EDR, DNS logs and packet-level validation before treating a candidate as an incident conclusion.

## 10.2.1 analyst UX hardening

This build adds an account-aware investigation experience on top of the 10.2 engine:

- Service navigation is hover-only on desktop; opening a menu does not require a click.
- Every service remains an isolated route/workspace.
- Signed-in users keep the account identity in the global navigation when moving between services.
- Completed authenticated analyses are stored as tenant scans instead of being downgraded to guest-only results.
- Guest results remain temporary for 24 hours.
- Result pages use a stable finding registry with finding ID, severity, confidence, status, affected asset, source, explanation and recommended next steps.
- PCAP results expose potential victim/compromised-host candidates, potential C2 candidates and external-source candidates as separate investigation pivots.
- Analysis pages expose 0-100 progress UX: real upload progress where the browser can measure it, plus explicit analysis/correlation/report stages while the server request is processing. The completed result is authoritative.
- Reports include PDF, HTML, JSON, Markdown, STIX 2.1, TXT, IOC CSV, flow CSV and a ZIP bundle.
- The local K4 AI analyst is an explainable evidence summarizer. It does not claim independent verification or attribution. External AI providers can be added as a separate connector.


## 10.3 Deep analyst build

This release follows the supplied `Pasted markdown(9).md` Universal Depth Rules. The runtime depth contract is applied to every service result. Each finding carries raw evidence references, interpretation, numeric confidence, timeline data, related IOC pivots, explicit threat-intelligence connector status and optional MITRE ATT&CK evidence.

The release adds a generated capability manifest at `data/spec/depth_capabilities.json`, 18 isolated deep service adapter packages, service/task/worker/schema/model/API route facades, an expanded passive PCAP forensic layer, a raw-evidence appendix UI, explainable risk signals, evidence chronology and a large report export suite.

External providers are not fabricated: VirusTotal, URLScan, MISP, OpenCTI, Shodan, Censys, sandbox vendors and SIEM/SOAR systems only report live results when their connectors and credentials are configured. Dynamic malware execution remains outside the web process.

## Network Artifacts Master Investigation Workbench — v13.0.0

The Network Artifacts workspace now includes a Master File Analysis flow layered on top of the v12 incident-response workbench. The file workflow provides heuristic risk-ranked artifact triage, malicious/high-risk filtering, sortable evidence inventory, K4-branded five-tab Deep File Dossiers (Network Provenance, Static & Code, Behavioral/Sandbox boundary, AI Threat Narrative, and Action & Integration), SHA-256 pivots, embedded indicator review, network-event provenance pivots, ATT&CK candidate context, response-rule exports, and dossier JSON export.

The 30,000-foot Attack Graph has also been expanded with higher-density topology, relationship-degree sizing, byte-weighted edges, node search/scope filtering, and click-through entity/edge dossiers. All attribution remains explicitly evidence-constrained: the UI distinguishes observed facts from hypotheses and does not fabricate sandbox, YARA, fuzzy-hash, actor, country, or campaign results when those capabilities are not actually configured.

## Network Artifacts Deep Investigation — v11.0.0

The PCAP Analyst has been expanded into a Network Artifacts Investigation Center covering PCAP/PCAPNG plus Zeek, Suricata, NetFlow/IPFIX, firewall, proxy, DNS and DHCP evidence. The deep subsystem includes original-artifact hashing, static file metadata, bounded TCP reassembly, passive signature-based file carving, protocol analysis, TLS metadata, DNS anomaly heuristics, behavioral detections, asset/victim/source profiling, cross-artifact correlation, MITRE candidate mapping, incident-response workflow, network graph metrics, unified timeline, IOC explorer, and HTML/PDF/JSON/CSV/STIX reporting.

Guest investigations use a per-job capability access key for report/download reliability. No uploaded payload is executed and no active network scanning is performed by this subsystem.


## K4 v12 IR Workbench
The Network Artifacts workspace now includes an interactive attack graph, victim/endpoint pivots, kill-chain timeline, bounded packet-level forensic drill-down, C2/beaconing analysis, exfiltration tracking, DNS intelligence, threat-intelligence evidence ledger, response blocklist generation, analyst disposition notes, chain-of-custody metadata, and executive/forensic reporting. The analysis remains passive and attribution is explicitly treated as a hypothesis requiring corroboration.

## Network Artifacts v14

The Network Artifacts workstation is a passive, case-centric PCAP/PCAPNG and network-log investigation suite. It includes interactive graph pivots, endpoint profiling, timeline reconstruction, bounded packet forensics, suspicious-file triage, a five-tab file dossier, response/report generation, scan timing, and a read-only catalog of 584 analyst-tool adapter entries. Third-party tools are not bundled or automatically executed.

The distributable ZIP includes a clean schema-only `data/phishhunter.db` so the project has one ready-to-use SQL store without shipping any development identities. Your administrator is created explicitly with `bootstrap_admin.py`.


## Network Artifacts v15 — Graph Studio

The v15 Network Artifacts UI adds a dedicated Graph Studio for high-density investigations. It preserves full IP/domain/host identifiers, provides an exact entity inventory with first/last seen timestamps, protocols, relationship counts and observed traffic, and adds graph zoom, pan, fit/reset, scope filtering, full-label mode, relationship-edge visibility, multiple layouts, entity export and high-volume entity pivots. The graph remains evidence-led: observed relationships are not automatically treated as compromise or attribution.


## v23 Backend Architecture

The project now includes a visible `Backend/` architecture facade mapping API, services, repositories, models, workers and analyzers to the canonical `phishhunter/` runtime. Admin and normal website authentication share the same host-scoped identity session.


## Identity and administration control plane

Phish-Hunter-k4 now has a database-first identity lifecycle and a full administrator control plane. The application does not create demo users automatically. The SQLite database ships clean and the first administrator is created explicitly with `bootstrap_admin.py`.

```powershell
python .\bootstrap_admin.py --email "admin@company.com" --password "Use-A-Strong-Password-Here" --organization "K4 Security Operations"
python .\run.py
```

Normal registration creates an Analyst account. Administrators can explicitly create additional Analyst or Administrator accounts from `/admin`, then enable/disable, permanently delete, reset passwords, change roles, review activity history, and inspect login-frequency analytics. User history is persisted in the `user_activity` SQL table. Passwords remain Argon2 hashes and are never rendered back to the UI.

The normal `/login` and administrator `/admin/login` surfaces read the same SQL-backed identity store. Successful and failed authentication events are recorded without storing plaintext passwords.

## v24.2 public experience update

The public website now keeps the same authenticated identity while moving between the application dashboard and public pages such as Blog, About, Documentation, Resources and Support. Public navigation no longer resets the UI to guest mode. The legacy v18 status strip and header search button were removed, and the account menu was simplified by removing Team, Billing & Plan, and API keys/API docs from the dropdown. The landing workspace now presents a clean evidence pipeline, while the Blog and About pages contain detailed project documentation. The footer includes the project logo, Telegram, LinkedIn, Facebook, GitHub and phone contact.

## V36 private user intelligence workspace

The authenticated analyst experience is now identity-scoped by `owner_user_id` for private analytical records. The main dashboard and `/workbench` show only the signed-in user's investigations, filenames/targets, evidence metadata, reports, cases, IOCs and activity history. The workbench includes selectable 30/90/180 day frequency telemetry, risk distribution, analyzer mix, activity heatmap, recent investigations, private scan dossiers and an identity relationship graph.

Administrators can use the control plane to open an individual user and review that identity's activity frequency, investigations, evidence inventory, reports, cases, indicators and historical account events. The administrator view is intentionally separated from the normal user's private workspace.

Normal self-registration creates an Analyst account and uses `Username` as the identity field. The first administrator is still created explicitly from the terminal with `bootstrap_admin.py`.

### Private data boundary

Normal authenticated API and HTML views filter private records with the authenticated user's owner id. Legacy `/api/v1/scans` is also owner-scoped for normal users, and case detail only returns linked scans/artifacts owned by that user. The normal team page shows only the signed-in user's identity; administrators retain directory visibility.

### First administrator

```powershell
python .\\bootstrap_admin.py --email "admin@company.com" --password "YOUR-ADMIN-PASSWORD" --organization "K4 Security Operations"
python .\\run.py
```

The application uses the configured SQLAlchemy database as the source of truth. Browser storage is not the account database. Passwords are stored as Argon2 hashes and are not rendered back to the interface.

## Tool module layout

The runtime package is `phishhunter/` and each major analyst/operations capability has its own rebuild boundary. See `docs/tool-modules.md` for the exact module tree and contract. This keeps future work isolated by tool while preserving the shared web, database, identity, security and reporting foundations.

## Vercel deployment (updated)

The root `index.py`, root `requirements.txt`, `.python-version`, and `vercel.json` are configured for Vercel's Python/FastAPI runtime. Import the **repository root** in Vercel (do not set `frontend/app` as the root directory). After deployment, verify `https://YOUR-DEPLOYMENT/health`.

Before exposing the app publicly, configure a unique `SECRET_KEY`, `PUBLIC_BASE_URL` (your Vercel HTTPS origin), `COOKIE_SECURE=true`, and a managed database using `DATABASE_URL`. A serverless function's local disk is ephemeral: SQLite, uploads, reports, and `data/storage` are not durable across deployments/instances. For persistent production use, attach managed PostgreSQL and external object storage, and run long-lived workers/PCAP analysis on Render, Railway, or a VPS. See [docs/hosting-vercel.md](docs/hosting-vercel.md) for the full deployment checklist and limitations.

## Deployment assistant

Use `python deploy_manager.py` for an interactive local setup/check/run/deploy menu. For one-command guidance, see [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md). The assistant uses a local `.venv` and keeps you out of Kali's externally managed system Python.

For Vercel, import the repository root. The committed `vercel.json` runs `python -m pip install -r requirements.txt`, and `pyproject.toml` explicitly limits setuptools package discovery to the active runtime packages. Vercel can provide a preview, but persistent accounts/evidence and long-running analysis require external database/storage/worker services; use Render, Railway, or a VPS for those requirements.
