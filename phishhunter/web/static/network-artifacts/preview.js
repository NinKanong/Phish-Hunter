// K4 Network Artifacts v18.0.0 — restored complete investigation renderer with resilient navigation.
(() => {
  "use strict";

  const state = {
    files: [],
    job: null,
    result: null,
    tab: "overview",
    capabilities: null,
    toolchain: null,
    jobs: [],
    timerHandle: null,
    graphMax: 180,
    graphLayout: "radial",
    error: "",
  };

  const root = document.getElementById("network-artifacts-root");
  if (!root) return;

  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[char]);

  const fmtBytes = (bytes) => {
    const n = Number(bytes || 0);
    if (!Number.isFinite(n) || n <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const power = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
    return `${(n / (1024 ** power)).toFixed(power ? 2 : 0)} ${units[power]}`;
  };

  const csrf = () => {
    const match = document.cookie.match(/(?:^|; )phishhunter_csrf=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : "";
  };

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    const token = csrf();
    if (token) headers.set("X-CSRF-Token", token);

    const response = await fetch(`/api/v1/pcap${path}`, {
      credentials: "include",
      ...options,
      headers,
    });

    const text = await response.text();
    let payload = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch (_) {
      payload = text;
    }

    if (!response.ok) {
      const detail = payload && typeof payload === "object" ? payload.detail : payload;
      throw new Error(detail || `${response.status} ${response.statusText}`);
    }
    return payload;
  }

  function badge(text, tone = "") {
    return `<span class="badge ${tone}">${esc(text)}</span>`;
  }

  function card(title, body, extra = "") {
    return `
      <section class="card">
        <div class="card-head"><h3>${esc(title)}</h3>${extra}</div>
        ${body}
      </section>`;
  }

  function metric(label, value, detail = "") {
    return `<div class="metric"><span>${esc(label)}</span><strong>${esc(value)}</strong>${detail ? `<small>${esc(detail)}</small>` : ""}</div>`;
  }

  function shell() {
    root.innerHTML = `
      <div class="network-app-shell">
        <aside class="network-sidebar">
          <div class="network-brand">
            <div class="network-brand-mark"><img src="/static/network-artifacts/k4-logo.svg?v=16.0.0" alt="K4"/></div>
            <div><b>PCAP Analyst</b><span>Network Artifacts</span></div>
          </div>
          <nav class="network-nav" aria-label="Network artifact investigation">
            ${[
              ["overview", "IR Command Center"],
              ["upload", "Evidence Intake"],
              ["artifacts", "Network Artifact Inventory"],
              ["graph", "30,000-Foot Attack Graph"],
              ["hosts", "Victim & Endpoint Profile"],
              ["timeline", "Kill Chain Timeline"],
              ["packets", "Packet-Level Forensics"],
              ["c2", "C2 & Beaconing Lab"],
              ["exfil", "Exfiltration Tracker"],
              ["dns", "DNS Intelligence"],
              ["threatintel", "Threat Intelligence Dossier"],
              ["files", "Files, Hashes & Carving"],
              ["protocols", "Protocols, TLS & JA4"],
              ["toolchain", "Open-source Toolchain / 100+"],
              ["iocs", "IOC & Pivot Explorer"],
              ["findings", "Detection & ATT&CK"],
              ["story", "Attack Narrative"],
              ["incident", "IR Action Center"],
              ["evidence", "Evidence & Chain of Custody"],
              ["report", "Executive / Forensic Report"],
              ["agent", "K4 Investigation Agent"],
            ].map(([id, label]) => `<button type="button" data-tab="${id}">${esc(label)}</button>`).join("")}
          </nav>
          <div class="network-side-foot">
            <b>Passive analysis boundary</b>
            <span>No uploaded payload execution.</span>
            <span>No active network scanning.</span>
            <span>Attribution is not inferred from packet evidence.</span>
          </div>
        </aside>

        <main class="network-main">
          <header class="network-topbar">
            <div>
              <span class="network-eyebrow">NETWORK FORENSICS / PCAP SIBLINGS</span>
              <h1>Network Artifacts Investigation Center</h1>
              <p>PCAP, Zeek, Suricata, NetFlow/IPFIX, firewall, proxy, DNS and DHCP evidence in one passive investigation workspace.</p>
            </div>
            <div class="network-top-actions">
              <div class="network-status"><i id="status-dot"></i><span id="status-text">Ready</span></div>
              <details class="sibling-menu">
                <summary>Analyst siblings</summary>
                <div class="sibling-popover">
                  <a href="/services/url-domain-analyst">URL &amp; Domain Analyst</a>
                  <a href="/services/email-analyst">Email Analyst</a>
                  <a href="/services/file-analyst">File / Malware Analyst</a>
                  <a href="/services/url-domain-analyst">URL &amp; Domain Analyst</a>
                  <a href="/services/ip-analyst">IP Analyst</a>
                  <a href="/services/pcap-analyst">PCAP Analyst</a>
                  <a href="/services/threat-intelligence">Threat Intelligence</a>
                </div>
              </details>
              <button type="button" class="secondary" id="refresh">Refresh</button>
            </div>
          </header>

          <div id="network-alert" class="network-alert hidden"></div>
          <div id="jobbar"></div>
          <div id="content" class="network-content"></div>
        </main>
      </div>`;

    // Delegated navigation: content is re-rendered frequently, so handlers must
    // live on the stable application root instead of individual transient buttons.
    root.addEventListener("click", (event) => {
      const target = event.target instanceof Element ? event.target.closest("[data-tab]") : null;
      if (!target || !root.contains(target)) return;
      event.preventDefault();
      state.tab = target.dataset.tab || "overview";
      render();
    });
    document.getElementById("refresh").addEventListener("click", () => loadCapabilities());
    if (!document.body.dataset.k4InspectorBound) {
      document.body.dataset.k4InspectorBound = "1";
      document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") closeInspector();
      });
    }
    render();
    loadCapabilities();
  }

  function setAlert(message = "") {
    state.error = message;
    const node = document.getElementById("network-alert");
    if (!node) return;
    node.classList.toggle("hidden", !message);
    node.innerHTML = message ? `<b>Workspace message</b><span>${esc(message)}</span>` : "";
  }

  async function loadCapabilities() {
    try {
      const data = await api("/capabilities");
      state.capabilities = data;
      try { state.toolchain = await api("/toolchain"); } catch (_) { state.toolchain = null; }
      setAlert("");
      await loadJobs();
      render();
    } catch (error) {
      setAlert(error.message || "Unable to load the Network Artifacts API.");
      render();
    }
  }

  async function loadJobs() {
    try {
      state.jobs = await api("/jobs");
    } catch (_) {
      state.jobs = [];
    }
  }

  function render() {
    document.querySelectorAll("[data-tab]").forEach((button) => {
      button.classList.toggle("active", button.dataset.tab === state.tab);
    });

    const content = document.getElementById("content");
    if (!content) return;

    if (state.tab === "upload") {
      content.innerHTML = uploadView();
      bindUpload();
      return;
    }
    if (state.tab === "toolchain") {
      content.innerHTML = toolchainView();
      bindToolchain();
      return;
    }

    if (!state.result) {
      if (state.tab === "overview") content.innerHTML = overviewEmpty();
      else if (state.tab === "artifacts" || state.tab === "files" || state.tab === "protocols" || state.tab === "hosts" || state.tab === "story" || state.tab === "incident") content.innerHTML = emptyView("No completed investigation", "Upload one or more authorized network artifacts and start an investigation.");
      else content.innerHTML = emptyView("No completed investigation", "Upload one or more authorized network artifacts and start an investigation.");
      return;
    }

    const views = {
      overview: commandCenterView,
      artifacts: artifactInventoryView,
      files: fileAnalysisView,
      protocols: protocolView,
      toolchain: toolchainView,
      hosts: victimProfileView,
      iocs: iocView,
      timeline: killChainTimelineView,
      graph: attackGraphView,
      packets: packetForensicsView,
      c2: c2View,
      exfil: exfiltrationView,
      dns: dnsIntelligenceView,
      threatintel: threatIntelDossierView,
      findings: findingsView,
      story: storyView,
      incident: incidentView,
      evidence: evidenceView,
      report: reportView,
      agent: agentView,
    };
    content.innerHTML = (views[state.tab] || dashboardView)();
  }

  function overviewEmpty() {
    const capabilityCount = state.capabilities ? Object.keys(state.capabilities.artifacts || {}).length : 0;
    return `<div class="hero-empty">
      <div class="hero-kicker">DEFENSIVE NETWORK ANALYSIS</div>
      <h2>Start a network investigation</h2>
      <p>Upload PCAP/PCAPNG or sibling network artifacts. The pipeline parses evidence, normalizes events, correlates indicators, builds a network graph, maps supported observations to MITRE ATT&CK and generates reports.</p>
      <div class="hero-actions"><button class="primary" data-tab="upload">Open Upload Center</button><a class="secondary-link" href="/login">Sign in to save investigations</a></div>
      <div class="capability-strip">${capabilityCount ? `${capabilityCount} artifact families available` : "Checking API capabilities…"}</div>
    </div>`;
  }

  function inventoryEmpty() {
    const artifacts = state.capabilities?.artifacts || {};
    return card("Supported artifact families", `<div class="family-grid">${Object.entries(artifacts).map(([key, value]) => `
      <div class="family-card"><b>${esc(value.label || key)}</b><span>${esc((value.extensions || []).join(", "))}</span><small>Detector: ${esc(key)}</small></div>`).join("")}</div>`);
  }

  function emptyView(title, text) {
    return `<div class="empty"><h2>${esc(title)}</h2><p>${esc(text)}</p><button type="button" class="primary" data-tab="upload">Open Upload Center</button></div>`;
  }

  function uploadView() {
    const files = state.files.map((file, index) => `
      <div class="selected-file">
        <div><b>${esc(file.name)}</b><span>${fmtBytes(file.size)}</span></div>
        <button type="button" data-remove-file="${index}" aria-label="Remove ${esc(file.name)}">Remove</button>
      </div>`).join("");

    const families = Object.entries(state.capabilities?.artifacts || {}).map(([key, value]) => `<span class="artifact-chip"><b>${esc(key)}</b> ${esc(value.label || "")}</span>`).join("");

    return `<div class="upload-layout">
      <section class="upload-center">
        <div class="drop" id="drop">
          <input id="files" hidden type="file" multiple accept=".pcap,.pcapng,.cap,.log,.tsv,.json,.csv,.txt">
          <div class="drop-icon">+</div>
          <h2>Drop network artifacts here</h2>
          <p>PCAP / PCAPNG, Zeek logs, Suricata EVE JSON, NetFlow/IPFIX and generic firewall, proxy, DNS or DHCP logs.</p>
          <span>Maximum 32 artifacts per investigation.</span>
        </div>
        <div class="selected-list">${files || `<div class="muted-box">No files selected.</div>`}</div>
        <div id="upload-error"></div>
        <div class="upload-actions"><button type="button" class="primary" id="start" ${state.files.length ? "" : "disabled"}>Start Investigation</button><button type="button" class="secondary" id="clear-files" ${state.files.length ? "" : "disabled"}>Clear</button></div>
      </section>
      ${card("Pipeline", `<div class="pipeline-list">${["Upload & validate", "Artifact classification", "Passive parsing", "Cross-artifact correlation", "Behavioral detections", "IOC normalization", "MITRE ATT&CK mapping", "Timeline + graph", "Report generation"].map((x, i) => `<div><i>${i + 1}</i><span>${esc(x)}</span></div>`).join("")}</div>`)}
      ${card("Artifact coverage", `<div class="chip-list">${families || `<span class="muted">Loading capabilities…</span>`}</div>`)}
    </div>`;
  }

  function bindUpload() {
    const input = document.getElementById("files");
    const drop = document.getElementById("drop");
    const start = document.getElementById("start");
    const clear = document.getElementById("clear-files");
    if (!input || !drop || !start) return;

    const showError = (message) => {
      const node = document.getElementById("upload-error");
      if (node) node.innerHTML = `<div class="error">${esc(message)}</div>`;
    };

    const setFiles = (list) => {
      state.files = Array.from(list || []).slice(0, 32);
      render();
    };

    drop.addEventListener("click", () => input.click());
    drop.addEventListener("dragover", (event) => {
      event.preventDefault();
      drop.classList.add("dragging");
    });
    drop.addEventListener("dragleave", () => drop.classList.remove("dragging"));
    drop.addEventListener("drop", (event) => {
      event.preventDefault();
      drop.classList.remove("dragging");
      setFiles(event.dataTransfer.files);
    });
    input.addEventListener("change", () => setFiles(input.files));

    document.querySelectorAll("[data-remove-file]").forEach((button) => {
      button.addEventListener("click", (event) => {
        event.stopPropagation();
        state.files.splice(Number(button.dataset.removeFile), 1);
        render();
      });
    });

    if (clear) clear.addEventListener("click", () => { state.files = []; render(); });

    start.addEventListener("click", async () => {
      if (!state.files.length) return;
      start.disabled = true;
      showError("");
      try {
        const form = new FormData();
        state.files.forEach((file) => form.append("files", file, file.name));
        const uploaded = await api("/upload", { method: "POST", body: form });
        state.job = uploaded;
        state.job.access_key = uploaded.access_key || state.job.access_key;
        state.result = null;
        state.tab = "overview";
        jobbar();
        await api(`/analyze/${encodeURIComponent(uploaded.job_id)}`, { method: "POST" });
        connectJob(uploaded.job_id);
      } catch (error) {
        showError(error.message || "Upload failed.");
        start.disabled = false;
      }
    });
  }

  function setJobStatus(status, progress, message) {
    const text = document.getElementById("status-text");
    const dot = document.getElementById("status-dot");
    if (text) text.textContent = status || "Ready";
    if (dot) dot.className = `status-dot ${status === "completed" ? "done" : status === "running" || status === "queued" ? "run" : ""}`;
    if (state.job) {
      state.job.status = status;
      state.job.progress = progress;
      state.job.message = message;
    }
  }

  function formatDuration(seconds){
    const n=Math.max(0,Number(seconds)||0); const h=Math.floor(n/3600), m=Math.floor((n%3600)/60), s=Math.floor(n%60);
    return h?`${h}h ${m}m ${s}s`:m?`${m}m ${s}s`:`${s}s`;
  }
  function jobbar() {
    const node = document.getElementById("jobbar");
    const job = state.job;
    if (!node || !job) return;
    const progress = Math.max(0, Math.min(100, Number(job.progress || 0)));
    const running=job.status==='running'||job.status==='queued';
    let elapsed=Number(job.duration_seconds||0);
    if(running && job.started_at){ elapsed=Math.max(0,(Date.now()-Date.parse(job.started_at))/1000); }
    const success=job.status==='completed';
    const failed=job.status==='failed';
    node.innerHTML = `<div class="jobbar ${success?'job-success':''} ${failed?'job-failed':''}"><div><b>${esc(success?'Successful':failed?'Analysis failed':job.status || "queued")}</b><span>${esc(job.message || "")}</span></div><div class="job-progress-meta"><span>${running?'Elapsed':'Scan time'} <strong>${formatDuration(elapsed)}</strong></span><span>Started ${esc(job.started_at?new Date(job.started_at).toLocaleTimeString(): '—')}</span></div><div class="progress"><i style="width:${progress}%"></i></div><strong>${progress}%</strong></div>${success?`<div class="scan-success"><span class="success-check">✓</span><div><b>Investigation completed successfully</b><small>Scan time: ${formatDuration(elapsed)} · ${esc(job.message||'All requested analysis stages completed')}</small></div><button type="button" class="secondary" data-tab="overview">Open case</button></div>`:''}`;
    setJobStatus(job.status, progress, job.message || "");
    if(running){ if(state.timerHandle) clearTimeout(state.timerHandle); state.timerHandle=window.setTimeout(jobbar,1000); }
  }

  function connectJob(jobId) {
    render();
    let socket = null;
    try {
      const protocol = location.protocol === "https:" ? "wss" : "ws";
      const access = state.job?.access_key ? `?access_key=${encodeURIComponent(state.job.access_key)}` : "";
      socket = new WebSocket(`${protocol}://${location.host}/api/v1/pcap/ws/${encodeURIComponent(jobId)}${access}`);
      socket.onmessage = async (event) => {
        try {
          const update = JSON.parse(event.data);
          state.job = { ...(state.job || {}), ...update };
          jobbar();
          if (update.status === "completed") {
            await loadCompletedJob(jobId);
            socket.close();
          } else if (update.status === "failed") {
            setAlert(update.message || "Analysis failed.");
            socket.close();
            render();
          }
        } catch (error) {
          setAlert(error.message || "Invalid job update received.");
        }
      };
      socket.onerror = () => pollJob(jobId);
      socket.onclose = () => {
        if (state.job && state.job.status !== "completed" && state.job.status !== "failed") pollJob(jobId);
      };
    } catch (_) {
      pollJob(jobId);
    }
  }

  async function pollJob(jobId) {
    try {
      const job = await api(`/jobs/${encodeURIComponent(jobId)}`);
      state.job = job;
      jobbar();
      if (job.status === "completed") {
        state.result = job.result;
        await loadJobs();
        render();
        return;
      }
      if (job.status === "failed") {
        setAlert(job.error || job.message || "Analysis failed.");
        render();
        return;
      }
      window.setTimeout(() => pollJob(jobId), 1000);
    } catch (error) {
      setAlert(error.message || "Unable to read job status.");
      render();
    }
  }

  async function loadCompletedJob(jobId) {
    const job = await api(`/jobs/${encodeURIComponent(jobId)}`);
    state.job = job;
    if (job.status === "completed") {
      state.result = job.result;
      // Authenticated investigations are persisted automatically by the backend.
      // Keep this idempotent fallback for older servers/databases so a completed
      // scan is never left out of the user's Dashboard/Workbench history.
      try {
        await api(`/jobs/${encodeURIComponent(jobId)}/save`, { method: "POST" });
      } catch (_) { /* backend auto-persistence is authoritative */ }
    }
    await loadJobs();
    render();
  }

  function safeArray(value){ return Array.isArray(value) ? value : []; }
  function clamp(n,min=0,max=100){ return Math.max(min,Math.min(max,Number(n)||0)); }
  function percent(n){ return `${clamp(n)}%`; }
  function normalizeIp(ip){ return String(ip||"").trim(); }
  function privateIp(ip){ try { const p=normalizeIp(ip).split('.').map(Number); return p.length===4 && ((p[0]===10)||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&p[1]===168)); } catch(_){return false;} }
  function graphNode(id){ return safeArray(state.result?.network_graph?.nodes).find(n=>String(n.id)===String(id)); }
  function graphEdge(id){ return safeArray(state.result?.network_graph?.edges).find((e,i)=>String(e.id||`${e.source}->${e.target}-${i}`)===String(id)); }
  function eventById(id){ return safeArray(state.result?.network_timeline || state.result?.timeline).find(e=>String(e.event_id||e.id)===String(id)); }
  function closeInspector(){
    const modal=document.getElementById("ir-inspector");
    if(modal) modal.hidden=true;
    document.body.classList.remove("ir-modal-open");
  }
  function openInspector(title, body){
    let modal=document.getElementById("ir-inspector");
    if(!modal){
      document.body.insertAdjacentHTML("beforeend",`<div id="ir-inspector" class="ir-modal" hidden><div class="ir-modal-backdrop" data-close-inspector></div><section class="ir-drawer" role="dialog" aria-modal="true" aria-label="Investigation pivot"><header><div><span class="network-eyebrow">INVESTIGATION PIVOT</span><h2 id="ir-inspector-title"></h2></div><div class="drawer-actions"><button type="button" class="secondary" data-back-workspace>Back to workspace</button><button type="button" class="secondary" data-close-inspector>Close</button></div></header><div id="ir-inspector-body"></div></section></div>`);
      modal=document.getElementById("ir-inspector");
      modal.addEventListener("click",(event)=>{
        const target=event.target instanceof Element ? event.target.closest("button,a,[data-close-inspector],[data-back-workspace],[data-tab],[data-file-tab],[data-file-dossier-json],[data-ir-export]") : null;
        if(!target || !modal.contains(target)) return;
        if(target.matches("[data-close-inspector],[data-back-workspace]")){ event.preventDefault(); closeInspector(); return; }
        if(target.matches("[data-tab]")){ event.preventDefault(); const tab=target.dataset.tab; closeInspector(); if(tab){ state.tab=tab; render(); } return; }
        if(target.matches("[data-file-tab]")){
          event.preventDefault();
          const dossier=target.closest('.file-dossier'); const idx=Number(dossier?.dataset.fileIndex||0); const f=normalizedFileRows()[idx];
          const panel=modal.querySelector('#file-panel');
          if(f && panel){ const selectedTab=target.dataset.fileTab||'provenance'; const wrapper=document.createElement('div'); wrapper.innerHTML=fileDossier(f,selectedTab); const inner=wrapper.querySelector('.file-panel'); if(inner) panel.innerHTML=inner.innerHTML; modal.querySelectorAll('[data-file-tab]').forEach(btn=>btn.classList.toggle('active',btn===target)); }
          return;
        }
        if(target.matches('[data-file-dossier-json]')){
          event.preventDefault(); const dossier=target.closest('.file-dossier'); const f=normalizedFileRows()[Number(dossier?.dataset.fileIndex||0)];
          if(f) downloadTextFile(`k4-file-dossier-${String(f.filename||'artifact').replace(/[^a-z0-9._-]/gi,'_')}.json`,JSON.stringify(f,null,2),'application/json');
          return;
        }
        if(target.matches('[data-ir-export]')){
          event.preventDefault(); const kind=target.dataset.irExport; const ext=kind==='csv'?'csv':kind==='sigma'?'yml':'rules'; downloadTextFile(`k4-ir-blocklist-${kind}.${ext}`,makeBlocklist(kind),kind==='csv'?'text/csv':'text/plain');
        }
      });
    }
    document.getElementById("ir-inspector-title").textContent=title;
    document.getElementById("ir-inspector-body").innerHTML=body;
    modal.hidden=false; document.body.classList.add("ir-modal-open");
  }
  function inspectorObject(obj){ return `<pre class="ir-json">${esc(JSON.stringify(obj||{},null,2))}</pre>`; }
  function severityTone(v){ const x=String(v||'').toLowerCase(); return x==='critical'||x==='high'?'bad':x==='medium'?'warn':'good'; }
  function commandCenterView(){
    const r=state.result||{}, summary=r.summary||{}, g=r.network_graph||{nodes:[],edges:[]}, b=r.behavioral_analysis||{}, ir=r.incident_response||{};
    const findings=safeArray(r.findings), events=safeArray(r.network_timeline||r.timeline), iocs=r.iocs||{};
    const high=findings.filter(x=>['critical','high'].includes(String(x.severity||'').toLowerCase())).length;
    const publicNodes=safeArray(g.nodes).filter(n=>n.scope==='public').length;
    const victims=safeArray(r.victim_profiles), assets=safeArray(r.asset_profiles);
    return `<div class="stack ir-command">
      <div class="ir-hero"><div><span class="network-eyebrow">K4 INCIDENT RESPONSE / CASE WORKBENCH</span><h2>Evidence-led investigation command center</h2><p>Start with relationships, pivot into the affected host, reconstruct the kill chain, prove behavior at packet level, then preserve and report the evidence.</p></div><div class="ir-case-state">${badge(r.verdict||'review',severityTone(r.verdict))}<strong>${esc(r.risk_score??0)}/100</strong><span>evidence risk score</span></div></div>
      <div class="metrics">${metric('Risk',r.risk_score??0,'evidence score')}${metric('Events',events.length,'normalized observations')}${metric('Nodes',g.nodes?.length||0,'relationship graph')}${metric('Findings',findings.length,`${high} high/critical`)}${metric('Victims',victims.length,'identity candidates')}${metric('Public peers',publicNodes,'external nodes')}</div>
      <div class="ir-stage-map">${[['01','ATTACK GRAPH','Map relationships','graph'],['02','VICTIM PROFILE','Who / where','hosts'],['03','KILL CHAIN','When / how','timeline'],['04','DEEP FORENSICS','C2 · exfil · DNS','c2'],['05','THREAT INTEL','Context / confidence','threatintel'],['06','PACKET PROOF','Raw evidence','packets'],['07','RESPONSE','Contain / preserve / report','incident']].map(x=>`<button type="button" data-tab="${x[3]}"><b>${x[0]}</b><strong>${x[1]}</strong><span>${x[2]}</span></button>`).join('')}</div>
      <div class="grid2">${card('Immediate investigation priorities',safeArray(findings).sort((a,b)=>(Number(b.score)||0)-(Number(a.score)||0)).slice(0,7).map(findingRow).join('')||'<div class="muted-box">No priority findings. Continue corroboration.</div>')}${card('Case evidence health',`<div class="ir-health"><div>${badge('Immutable source hashes','good')}<span>${safeArray(r.artifacts).length} source artifacts</span></div><div>${badge('Passive analysis','good')}<span>Uploaded payloads are not executed</span></div><div>${badge('Attribution guarded','warn')}<span>Network evidence alone does not prove actor identity</span></div><div>${badge('Follow-up collection','warn')}<span>${safeArray(ir.follow_up_evidence).length} recommended collection item(s)</span></div></div>`)}</div>
      ${card('Network artifact coverage',`<div class="ir-coverage">${Object.entries(state.capabilities?.artifacts||{}).map(([k,v])=>`<div><b>${esc(k)}</b><span>${esc(v?.description||v?.label||'supported')}</span>${badge('supported','good')}</div>`).join('')||'<div class="muted-box">Capability manifest unavailable.</div>'}</div>`)}
    </div>`;
  }
  function graphEntityInventory(allNodes, allEdges){
    const degree=new Map(allNodes.map(n=>[String(n.id),0]));
    const bytes=new Map(allNodes.map(n=>[String(n.id),0]));
    const protocols=new Map(allNodes.map(n=>[String(n.id),new Set()]));
    const first=new Map(), last=new Map();
    allEdges.forEach(e=>{
      const a=String(e.source||""), b=String(e.target||"");
      degree.set(a,(degree.get(a)||0)+1); degree.set(b,(degree.get(b)||0)+1);
      const v=Number(e.bytes||0)||0; bytes.set(a,(bytes.get(a)||0)+v); bytes.set(b,(bytes.get(b)||0)+v);
      const proto=String(e.protocol||e.label||""); if(proto){protocols.get(a)?.add(proto); protocols.get(b)?.add(proto);}
      if(e.first_seen){ if(!first.has(a)||String(e.first_seen)<String(first.get(a))) first.set(a,e.first_seen); if(!first.has(b)||String(e.first_seen)<String(first.get(b))) first.set(b,e.first_seen); }
      if(e.last_seen){ if(!last.has(a)||String(e.last_seen)>String(last.get(a))) last.set(a,e.last_seen); if(!last.has(b)||String(e.last_seen)>String(last.get(b))) last.set(b,e.last_seen); }
    });
    return allNodes.map(n=>({node:n,relationships:degree.get(String(n.id))||0,bytes:bytes.get(String(n.id))||0,protocols:[...(protocols.get(String(n.id))||new Set())],first_seen:first.get(String(n.id))||"",last_seen:last.get(String(n.id))||""})).sort((a,b)=>b.relationships-a.relationships);
  }

  function attackGraphView(){ return attackGraphViewImpl(); }
  function attackGraphViewImpl(){
    const g=state.result?.network_graph||{nodes:[],edges:[]};
    const allNodes=safeArray(g.nodes), allEdges=safeArray(g.edges);
    const maxNodes=Number(state.graphMax||180);
    const degree=new Map(allNodes.map(n=>[String(n.id),0]));
    allEdges.forEach(e=>{degree.set(String(e.source),(degree.get(String(e.source))||0)+1);degree.set(String(e.target),(degree.get(String(e.target))||0)+1);});
    const nodes=[...allNodes].sort((a,b)=>(degree.get(String(b.id))||0)-(degree.get(String(a.id))||0)).slice(0,maxNodes);
    const allowed=new Set(nodes.map(n=>String(n.id)));
    const edges=allEdges.filter(e=>allowed.has(String(e.source))&&allowed.has(String(e.target))).slice(0,Math.max(1200,maxNodes*4));
    const width=Math.max(1500,Math.min(3000,Math.sqrt(nodes.length||1)*180));
    const height=Math.max(850,Math.min(2200,Math.sqrt(nodes.length||1)*130));
    const cx=width/2, cy=height/2;
    const positions=new Map();
    if(state.graphLayout==='grid'){
      const cols=Math.max(8,Math.ceil(Math.sqrt(nodes.length))); const gapX=width/cols, gapY=Math.max(82,height/Math.ceil(nodes.length/cols));
      nodes.forEach((n,i)=>positions.set(String(n.id),{x:(i%cols)*gapX+gapX/2,y:Math.floor(i/cols)*gapY+50}));
    } else {
      const center=nodes[0];
      if(center) positions.set(String(center.id),{x:cx,y:cy});
      const remaining=nodes.slice(center?1:0);
      let cursor=0, ring=1;
      while(cursor<remaining.length){
        const count=Math.min(remaining.length-cursor,Math.max(8,Math.round(8*ring))); const radius=110+ring*105;
        for(let j=0;j<count;j++){const n=remaining[cursor+j];const angle=(j/count)*Math.PI*2+(ring%2)*0.18;positions.set(String(n.id),{x:cx+Math.cos(angle)*Math.min(radius,width*.43),y:cy+Math.sin(angle)*Math.min(radius,height*.40)});}
        cursor+=count; ring++;
      }
    }
    const edgeLines=edges.map((e,i)=>{const a=positions.get(String(e.source)),b=positions.get(String(e.target));if(!a||!b)return '';const id=e.id||`${e.source}->${e.target}-${i}`;const widthPx=Math.max(1,Math.min(7,1+Math.log10(Number(e.bytes||1)+1)/2));return `<g><line class="ir-edge" data-edge="${esc(id)}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" style="stroke-width:${widthPx}px"/><title>${esc(`${e.source} → ${e.target} · ${e.protocol||e.label||'relationship'} · ${fmtBytes(e.bytes||0)} · ${e.first_seen||''} → ${e.last_seen||''}`)}</title></g>`;}).join('');
    const circles=nodes.map(n=>{const p=positions.get(String(n.id));const type=String(n.type||'').toLowerCase();const cls=n.scope==='public'||type.includes('attacker')?'attacker':type.includes('victim')||n.scope==='private'?'victim':'clean';const d=degree.get(String(n.id))||0;const radius=Math.min(34,18+Math.sqrt(d)*3.2);return `<g class="ir-node" data-node="${esc(n.id)}"><circle class="${cls}" cx="${p.x}" cy="${p.y}" r="${radius}"></circle><text x="${p.x}" y="${p.y-3}" text-anchor="middle" class="node-label">${esc(String(n.id))}</text><text class="node-degree" x="${p.x}" y="${p.y+11}" text-anchor="middle">${d} links</text><title>${esc(String(n.id))}</title></g>`;}).join('');
    const publicCount=nodes.filter(n=>n.scope==='public').length, privateCount=nodes.filter(n=>n.scope==='private').length;
    return `<div class="stack"><div class="ir-graph-toolbar"><div><b>30,000-foot attack graph — forensic topology map</b><span>${nodes.length} displayed / ${allNodes.length} total entities · ${edges.length} displayed / ${allEdges.length} total relationships. Click a node or connection for a full evidence dossier.</span></div><div class="legend"><span><i class="attacker"></i> External / public</span><span><i class="victim"></i> Internal / victim candidate</span><span><i class="clean"></i> Internal / other</span></div></div>${card('Graph controls',`<div class="file-controls"><label>Find node <input id="graph-search" placeholder="IP, hostname, domain…"></label><label>Scope <select id="graph-scope"><option value="all">All</option><option value="public">Public</option><option value="private">Private</option></select></label><label>Density <select id="graph-density"><option value="100">100 nodes</option><option value="180" selected>180 nodes</option><option value="300">300 nodes</option><option value="500">500 nodes</option></select></label><label>Layout <select id="graph-layout"><option value="radial" selected>Radial evidence rings</option><option value="grid">Evidence grid</option></select></label><span class="muted">Node size = relationship degree. Edge width = relative observed byte volume. Broadcast/multicast noise can be hidden by filtering.</span></div>`)}${card('Interactive relationship map',`<div class="ir-graph"><svg id="ir-graph-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Interactive network attack graph">${edgeLines}${circles}</svg></div><div class="graph-insight-strip"><span>${metric('External',publicCount,'public-scope nodes')}</span><span>${metric('Internal',privateCount,'private-scope nodes')}</span><span>${metric('High degree',nodes.filter(n=>(degree.get(String(n.id))||0)>=10).length,'10+ observed links')}</span><span>${metric('Edges',edges.length,'displayed relationships')}</span></div><p class="muted">Every graph relationship is an observation from the submitted evidence. Compromise, intent, actor identity and geographic attribution remain separate hypotheses requiring corroboration.</p>`)}${card('Complete Network Entity Inventory',`<div class="table-wrap graph-entity-table"><table><thead><tr><th>Full entity</th><th>Scope</th><th>Type</th><th>Relationships</th><th>Observed volume</th><th>Protocols</th><th>First seen</th><th>Last seen</th><th>Action</th></tr></thead><tbody>${graphEntityInventory(allNodes,allEdges).slice(0,2000).map((row)=>`<tr><td><code>${esc(row.node.id)}</code></td><td>${badge(row.node.scope||'unknown',row.node.scope==='public'?'bad':'good')}</td><td>${esc(row.node.type||'observed')}</td><td>${row.relationships}</td><td>${fmtBytes(row.bytes)}</td><td>${esc(row.protocols.join(', ')||'—')}</td><td>${esc(row.first_seen||'—')}</td><td>${esc(row.last_seen||'—')}</td><td><button type="button" class="primary" data-node="${esc(row.node.id)}">Open dossier</button></td></tr>`).join('')||'<tr><td colspan="9">No network entities were produced.</td></tr>'}</tbody></table></div><p class="muted">This inventory preserves complete identifiers even when the graph is too dense to label every entity legibly.</p>`)}${card('Node / edge pivot model',`<div class="stage-grid"><div><b>External node</b><span>Threat dossier → IOC context → infrastructure evidence → packet proof.</span></div><div><b>Victim node</b><span>Endpoint profile → complete observed activity → timeline → files and evidence.</span></div><div><b>Connection</b><span>Protocol → bytes → first/last seen → packet-level proof → related indicators.</span></div><div><b>Artifact relationship</b><span>File/hash → network provenance → deep file dossier → response rules.</span></div></div>`)}</div>`;
  }

  function hostProfileDetail(h){ const ip=h?.ip||h?.id||'unknown'; const events=safeArray(state.result?.network_timeline||state.result?.timeline).filter(e=>e.src_ip===ip||e.dst_ip===ip); return `<div class="drawer-grid">${metric('IP',ip)}${metric('Hostname',(h?.hostnames||[])[0]||'not observed')}${metric('Peers',h?.peer_count||0)}${metric('Bytes',fmtBytes(h?.bytes||0))}</div>${card('Observed identity',inspectorObject(h))}${card('Full activity',`<div class="table-wrap"><table><thead><tr><th>Time</th><th>Flow</th><th>Protocol</th><th>Message</th></tr></thead><tbody>${events.slice(0,500).map(e=>`<tr><td>${esc(e.timestamp||'')}</td><td><code>${esc(e.src_ip||'')} → ${esc(e.dst_ip||'')}</code></td><td>${esc(e.protocol||e.event_type||'')}</td><td>${esc(e.message||e.hostname||'')}</td></tr>`).join('')}</tbody></table></div>`)}`; }
  function victimProfileView(){ const victims=safeArray(state.result?.victim_profiles), assets=safeArray(state.result?.asset_profiles); return `<div class="stack">${card('Victim & endpoint profiling',`<p class="muted">Identity is built only from observed network evidence. OS and user identity are hypotheses unless corroborated by endpoint telemetry.</p><div class="profile-grid">${(victims.length?victims:assets).slice(0,100).map((h,i)=>`<button type="button" class="profile-card" data-host-index="${i}"><span>${esc(h.ip||'unknown')}</span><b>${esc((h.hostnames||[])[0]||'Hostname not observed')}</b><small>${esc(h.peer_count||0)} peers · ${fmtBytes(h.bytes||0)}</small></button>`).join('')||'<div class="muted-box">No host profiles.</div>'}</div>`)}${card('Endpoint investigation checklist',`<div class="checklist">${['Confirm hostname and logged-in identity from EDR/AD','Correlate DNS, proxy and firewall activity','Collect endpoint process and PowerShell telemetry','Validate persistence and credential-access evidence','Preserve volatile evidence before remediation'].map((x,i)=>`<label><input type="checkbox" data-ir-check="${i}"> <span>${x}</span></label>`).join('')}</div>`)}</div>`; }
  function killChainTimelineView(){ const events=safeArray(state.result?.network_timeline||state.result?.timeline); const mapped=events.map((e,i)=>{const text=`${e.message||''} ${e.hostname||''}`.toLowerCase();let phase='Discovery / Network Activity'; if(/phish|mail|url|initial/.test(text))phase='Initial Access'; else if(/get |download|exec|powershell|script/.test(text))phase='Execution'; else if(/beacon|c2|command/.test(text))phase='Command & Control'; else if(/upload|post|exfil|outbound/.test(text))phase='Exfiltration'; return {...e,phase,index:i};}); return `<div class="stack">${card('Kill chain reconstruction',`<div class="killchain">${['Initial Access','Execution','Persistence','Privilege / Credential Access','Discovery','Lateral Movement','Command & Control','Collection','Exfiltration'].map((x,i)=>`<div><b>${String(i+1).padStart(2,'0')}</b><span>${x}</span></div>`).join('')}</div>`)}${card(`Event timeline — ${mapped.length} observations`,`<div class="ir-timeline">${mapped.slice(0,1500).map((e,i)=>`<button type="button" class="timeline-event" data-event-id="${esc(e.event_id||`EV-${i+1}`)}"><time>${esc(e.timestamp||'No timestamp')}</time><strong>${esc(e.phase)}</strong><span>${esc(e.src_ip||'')} ${e.dst_ip?`→ ${esc(e.dst_ip)}`:''} · ${esc(e.protocol||e.event_type||'')}</span><p>${esc(e.message||e.hostname||'No message')}</p></button>`).join('')||'<div class="muted-box">No timeline events.</div>'}</div>`)}</div>`; }
  function packetForensicsView(){ const p=state.result?.protocol_analysis?.pcap||{}; const conv=safeArray(p.conversations); return `<div class="stack">${card('Packet-level forensic workstation',`<div class="packet-toolbar"><input id="packet-filter" placeholder="Filter IP, port, protocol, hostname…"><button type="button" class="primary" id="packet-search">Search packets</button><span class="muted">Raw packet drill-down is bounded and read-only.</span></div><div class="table-wrap"><table><thead><tr><th>Conversation</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>First seen</th><th>Last seen</th><th>Action</th></tr></thead><tbody>${conv.slice(0,1000).map((c,i)=>`<tr><td><code>${esc(c.src_ip)}:${esc(c.src_port)} → ${esc(c.dst_ip)}:${esc(c.dst_port)}</code></td><td>${esc(c.protocol)}</td><td>${esc(c.packets)}</td><td>${fmtBytes(c.bytes)}</td><td>${esc(c.first_seen||'')}</td><td>${esc(c.last_seen||'')}</td><td><button class="secondary packet-detail" data-conv-index="${i}" type="button">View evidence</button></td></tr>`).join('')||'<tr><td colspan="7">No packet conversations were parsed.</td></tr>'}</tbody></table></div>`)}${card('Protocol dissection',inspectorObject({format:p.format,link_type:p.link_type,snaplen:p.snaplen,raw_packet_count:p.raw_packet_count,parsed_packet_count:p.parsed_packet_count,limits:p.limits}))}</div>`; }
  function c2View(){ const b=state.result?.behavioral_analysis||{}, items=safeArray(b.beaconing_candidates); return `<div class="stack">${card('C2 & beaconing analysis',`<div class="metrics">${metric('Candidates',items.length,'periodicity hypotheses')}${metric('Streams',state.result?.protocol_analysis?.pcap?.tcp_streams?.length||0,'bounded reassembly')}${metric('TLS observations',state.result?.tls_analysis?.observations?.length||0,'if available')}</div><p class="muted">Regularity is a behavioral signal, not an automatic malware identification. Extracted configurations require binary or endpoint evidence.</p>`)}${card('Beacon candidates',items.map((x,i)=>`<button type="button" class="forensic-row" data-beacon-index="${i}"><b>${esc(x.source||x.src_ip||'candidate')}</b><span>${esc(x.destination||x.dst_ip||x.host||'')}</span><small>confidence ${esc(x.confidence??'—')} · ${esc(x.reason||'')}</small></button>`).join('')||'<div class="muted-box">No beaconing candidates.</div>')}${card('C2 validation checklist',`<div class="checklist">${['Measure inter-arrival times and jitter','Compare destination infrastructure across cases','Correlate DNS → TLS SNI → connection sequence','Validate with endpoint process/network telemetry','Do not label a malware family without corroborating evidence'].map((x,i)=>`<label><input type="checkbox"><span>${x}</span></label>`).join('')}</div>`)}</div>`; }
  function exfiltrationView(){ const items=safeArray(state.result?.behavioral_analysis?.exfiltration_candidates); const events=safeArray(state.result?.network_timeline||state.result?.timeline); const outbound=events.filter(e=>privateIp(e.src_ip)&&!privateIp(e.dst_ip)); return `<div class="stack">${card('Data exfiltration tracker',`<div class="metrics">${metric('Candidates',items.length,'behavioral hypotheses')}${metric('Outbound events',outbound.length,'private → external')}${metric('Outbound bytes',fmtBytes(outbound.reduce((n,e)=>n+Number(e.bytes||e.byte_count||0),0)),'when byte counts exist')}</div>`)}${card('Exfiltration candidates',items.map(x=>`<div class="finding-row"><div><b>${esc(x.source||x.src_ip||'candidate')}</b><p>${esc(x.reason||'')}</p><small>Destination: ${esc(x.destination||x.dst_ip||'unknown')} · confidence ${esc(x.confidence??'—')}</small></div>${badge('candidate','warn')}</div>`).join('')||'<div class="muted-box">No exfiltration candidates.</div>')}${card('Outbound traffic ledger',`<div class="table-wrap"><table><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Bytes</th><th>Host</th></tr></thead><tbody>${outbound.slice(0,1000).map(e=>`<tr><td>${esc(e.timestamp||'')}</td><td><code>${esc(e.src_ip||'')}</code></td><td><code>${esc(e.dst_ip||'')}</code></td><td>${esc(e.protocol||e.event_type||'')}</td><td>${fmtBytes(e.bytes||e.byte_count||0)}</td><td>${esc(e.hostname||'')}</td></tr>`).join('')||'<tr><td colspan="6">No byte-level outbound records.</td></tr>'}</tbody></table></div>`)}</div>`; }
  function dnsIntelligenceView(){ const b=state.result?.behavioral_analysis||{}, d=safeArray(state.result?.protocol_analysis?.pcap?.dns_observations), tunnels=safeArray(b.dns_tunneling_candidates), dga=safeArray(b.dga_candidates); return `<div class="stack">${card('DNS intelligence',`<div class="metrics">${metric('DNS observations',d.length,'packet-level DNS')}${metric('Tunneling candidates',tunnels.length,'heuristic')}${metric('DGA candidates',dga.length,'heuristic')}</div>`)}${card('DNS tunneling candidates',tunnels.map(x=>`<details><summary>${esc(x.domain||x.hostname||x.source||'candidate')} · confidence ${esc(x.confidence??'—')}</summary>${inspectorObject(x)}</details>`).join('')||'<div class="muted-box">No DNS tunneling candidates.</div>')}${card('Domain anomaly ledger',dga.map(x=>`<details><summary>${esc(x.domain||x.hostname||'domain')}</summary>${inspectorObject(x)}</details>`).join('')||'<div class="muted-box">No DGA-like candidates.</div>')}${card('Raw DNS observations',`<div class="table-wrap"><table><thead><tr><th>Time</th><th>Source</th><th>Resolver</th><th>Details</th></tr></thead><tbody>${d.slice(0,1000).map(x=>`<tr><td>${esc(x.timestamp||'')}</td><td><code>${esc(x.src_ip||'')}</code></td><td><code>${esc(x.dst_ip||'')}</code></td><td><pre>${esc(JSON.stringify(x.details||{},null,2))}</pre></td></tr>`).join('')||'<tr><td colspan="4">No DNS observations.</td></tr>'}</tbody></table></div>`)}</div>`; }
  function threatIntelDossierView(){ const ledger=state.result?.threat_intel_ledger||{}, external=safeArray(state.result?.external_sources); const entries=Object.entries(ledger); return `<div class="stack">${card('Threat intelligence dossier',`<div class="ir-warning">Network evidence can support infrastructure/context hypotheses, but it cannot by itself prove a threat actor identity. Keep actor names, country, motivation and campaign links explicitly confidence-scored and sourced.</div><div class="metrics">${metric('Enrichment records',entries.length,'IOC/provider ledger')}${metric('External sources',external.length,'observed candidates')}${metric('Configured providers',safeArray(state.result?.enrichment?.providers).length,'connector status')}</div>`)}${card('IOC enrichment ledger',`<div class="table-wrap"><table><thead><tr><th>Indicator</th><th>Status</th><th>Providers</th><th>Reason / evidence</th></tr></thead><tbody>${entries.slice(0,1000).map(([k,v])=>`<tr><td><code>${esc(v?.ioc||k)}</code></td><td>${badge(v?.status||'unknown',v?.status==='malicious'?'bad':'')}</td><td>${esc(safeArray(v?.providers).join(', ')||'not configured')}</td><td>${esc(v?.reason||'')}</td></tr>`).join('')||'<tr><td colspan="4">No enrichment records.</td></tr>'}</tbody></table></div>`)}${card('Attribution worksheet',`<div class="attribution-grid">${['Observed infrastructure','Certificate / TLS clues','Passive DNS context','Related campaign evidence','Actor technique overlap','Confidence and counter-evidence'].map(x=>`<div><b>${x}</b><textarea placeholder="Record sourced evidence; do not turn a hypothesis into a fact."></textarea></div>`).join('')}</div>`)}</div>`; }
  function dashboardView() {
    const result = state.result;
    const summary = result.summary || {};
    const findings = Array.isArray(result.findings) ? result.findings : [];
    const graph = result.network_graph || { nodes: [], edges: [] };
    const sources = Object.entries(summary.sources || {}).map(([key, value]) => `${key}: ${value}`).join(" · ");
    return `<div class="stack">
      <div class="metrics">
        ${metric("Risk score", result.risk_score ?? 0, "0–100 evidence score")}
        ${metric("Artifacts", result.artifact_count ?? 0, (result.artifact_types || []).join(", ") || "none")}
        ${metric("Events", summary.events ?? 0, sources || "normalized observations")}
        ${metric("Findings", findings.length, `${graph.nodes.length} nodes / ${graph.edges.length} edges`)}
      </div>
      ${card("Investigation telemetry", `<div class="mini-charts"><div><span>Risk</span><div class="bar"><i style="width:${Math.max(0, Math.min(100, Number(result.risk_score || 0)))}%"></i></div><b>${esc(result.risk_score ?? 0)}/100</b></div><div><span>Findings</span><div class="bar"><i style="width:${Math.min(100, findings.length * 10)}%"></i></div><b>${esc(findings.length)}</b></div><div><span>Graph density</span><div class="bar"><i style="width:${Math.min(100, graph.nodes.length ? (graph.edges.length / Math.max(graph.nodes.length,1))*25 : 0)}%"></i></div><b>${esc(graph.edges.length)} edges</b></div></div>`)}
      <div class="grid2">
        ${card("Disposition", `${badge(result.verdict || "unknown", result.verdict === "review_required" ? "warn" : "good")}<p class="muted">The disposition is evidence-oriented. Candidate detections should be corroborated with surrounding telemetry.</p>`)}
        ${card("Analysis stages", `<div class="stage-grid">${(result.agent_controller || []).map((stage) => `<div><b>${esc(stage.stage || stage.name || "stage")}</b><span>${esc(stage.status || "planned")}</span></div>`).join("") || `<div><b>Passive engine</b><span>Completed</span></div>`}</div>`)}
      </div>
      ${card("Top findings", findings.slice(0, 12).map(findingRow).join("") || `<div class="muted-box">No behavioral findings were generated from the supplied evidence.</div>`)}
      ${card("Investigation narrative", `<div class="narrative">${esc(result.narrative || "No narrative was generated.")}</div>`)}
    </div>`;
  }

  function artifactInventoryView() {
    const artifacts = state.result.artifacts || [];
    return card("Artifact inventory", `<div class="table-wrap"><table><thead><tr><th>Artifact</th><th>Type</th><th>Size</th><th>SHA-256</th><th>Events</th></tr></thead><tbody>${artifacts.map((item) => {
      const a = item.artifact || {};
      return `<tr><td><b>${esc(a.filename)}</b><small>${esc(a.artifact_id)}</small></td><td>${badge(a.artifact_type || "unknown")}</td><td>${fmtBytes(a.size_bytes)}</td><td><code>${esc(a.sha256 || "")}</code></td><td>${esc(item.event_count ?? 0)}</td></tr>`;
    }).join("")}</tbody></table></div>`);
  }

  function fileRiskScore(f){
    let score=8;
    const entropy=Number(f.entropy||0);
    const keywords=safeArray(f.suspicious_keywords);
    const indicators=f.indicators||{};
    if(entropy>=7.5) score+=22; else if(entropy>=7) score+=14;
    if(f.suspicious_extension) score+=20;
    score+=Math.min(25,keywords.length*6);
    score+=Math.min(15,Object.values(indicators).flat().length*2);
    if(/PE|ELF|executable|script|macro|pdf/i.test(String(f.type||f.kind||''))) score+=8;
    return clamp(Math.round(score));
  }
  function normalizedFileRows(){
    const files=safeArray(state.result?.file_analysis).map((x,i)=>({...x,source:'uploaded-artifact',row_id:`uploaded-${i}`}));
    const extracted=safeArray(state.result?.extracted_files).map((x,i)=>({...((x.profile)||{}),filename:x.filename,hashes:x.hashes,sha256:x.sha256,size_bytes:x.size,source:'passive-carving',id:x.id,archive:x.archive,source_stream:x.source_stream,offset:x.offset,row_id:`carved-${i}`,extraction_note:x.extraction_note}));
    return files.concat(extracted).map((f,i)=>({...f,index:i,risk:fileRiskScore(f)})).sort((a,b)=>b.risk-a.risk);
  }
  function fileContext(f){
    const needle=String(f.filename||'').toLowerCase();
    const sha=String(f.sha256||f.hashes?.sha256||'').toLowerCase();
    const events=safeArray(state.result?.network_timeline||state.result?.timeline).filter(e=>{const b=JSON.stringify(e).toLowerCase();return (needle&&b.includes(needle))||(sha&&b.includes(sha));});
    const sources=[...new Set(events.map(e=>e.src_ip).filter(Boolean))].slice(0,3);
    const victims=[...new Set(events.map(e=>e.dst_ip).filter(Boolean))].slice(0,3);
    return {events,sources,victims,timestamp:events[0]?.timestamp||f.timestamp||'not observed'};
  }
  function fileDossier(f,activeTab="provenance"){
    const h=f.hashes||{}; const inds=f.indicators||{}; const strings=safeArray(f.strings_sample); const keywords=safeArray(f.suspicious_keywords);
    const events=safeArray(state.result?.network_timeline||state.result?.timeline).filter(e=>{
      const blob=JSON.stringify(e).toLowerCase(); return f.filename && blob.includes(String(f.filename).toLowerCase());
    });
    const urls=safeArray(inds.urls), domains=safeArray(inds.domains), ips=safeArray(inds.ips);
    const claimed=String(f.filename||'').split('.').pop()||'unknown';
    const trueType=f.type||'unknown';
    const networkProof=events.length?events.slice(0,80).map(e=>`<div class="forensic-row"><b>${esc(e.timestamp||'no timestamp')}</b><span>${esc(e.src_ip||'')} → ${esc(e.dst_ip||'')}</span><small>${esc(e.protocol||e.event_type||'')} · ${esc(e.message||e.hostname||'')}</small></div>`).join(''):'<div class="muted-box">No event explicitly references this carved filename. Use hash/domain/stream pivots for provenance.</div>';
    const tab=(id,label,body,active=false)=>`<button type="button" class="file-tab ${active?'active':''}" data-file-tab="${id}"><span class="k4-mini-logo">K4</span>${esc(label)}</button>`;
    const panels={
      provenance:`${card('Download chain & network provenance',`<div class="chain-flow"><span>Observed network evidence</span><b>→</b><span>Potential transfer</span><b>→</b><span>${esc(f.filename||'artifact')}</span></div><p class="muted">The platform only claims a download chain when the network evidence contains corroborating metadata. It will not invent email/referrer/packet numbers that were not observed.</p>${card('Matching network observations',networkProof)}`)}${card('Network fingerprints',`<div class="drawer-grid">${metric('Source stream',f.source_stream||'not recorded')}${metric('Offset',f.offset??'—')}${metric('URLs',urls.length)}${metric('Domains',domains.length)}</div><div class="chips">${urls.slice(0,30).map(x=>`<code>${esc(x)}</code>`).join('')}${domains.slice(0,30).map(x=>`<code>${esc(x)}</code>`).join('')}</div>`)}${card('Victim / packet pivot',`<p class="muted">Select a matching event or use Packet-Level Forensics to inspect the bounded packet stream. Exact packet numbers are shown only when available from the packet drill-down API.</p><button type="button" class="primary" data-tab="packets">Open Packet-Level Forensics</button>`)}`,
      static:`${card('File identity',`<div class="drawer-grid">${metric('Risk',`${f.risk}/100`,f.risk>=80?'high-priority triage':'heuristic score')}${metric('Claimed extension',`.${claimed}`)}${metric('True type',trueType)}${metric('MIME',f.mime||'unknown')}</div><div class="ir-warning">Static triage is evidence-based and non-executing. A high score is a prioritization signal, not a malware verdict.</div>`)}${card('Cryptographic identity',`<div class="hash-stack"><div><b>MD5</b><code>${esc(h.md5||'')}</code></div><div><b>SHA-1</b><code>${esc(h.sha1||'')}</code></div><div><b>SHA-256</b><code>${esc(h.sha256||f.sha256||'')}</code></div></div>`)}${card('Entropy, strings & heuristics',`<div class="metrics">${metric('Size',fmtBytes(f.size_bytes||f.size||0))}${metric('Entropy',f.entropy??'—','0–8 scale')}${metric('Strings',f.strings_count??strings.length)}${metric('Keywords',keywords.length)}</div><div class="chips">${keywords.map(x=>badge(x,'bad')).join('')||badge('No suspicious keyword observed','good')}</div>`)}${card('Extracted strings',strings.slice(0,250).map(x=>`<div class="string-line"><code>${esc(x)}</code></div>`).join('')||'<div class="muted-box">No sampled strings.</div>')}${card('Static indicators',inspectorObject(inds))}`,
      behavior:`${card('Behavioral / sandbox simulation boundary',`<div class="ir-warning">This workspace performs passive/static analysis of uploaded evidence. It does not execute the recovered file. Process trees, registry writes, file drops and live C2 configuration are shown only when supported by observed evidence or an external sandbox connector.</div>`)}${card('Behavioral signals derived from static evidence',`<div class="stage-grid"><div><b>Script / interpreter activity</b><span>${keywords.filter(x=>/powershell|cmd|wscript|cscript|mshta|rundll32/i.test(x)).join(', ')||'Not observed'}</span></div><div><b>Network callbacks</b><span>${[...urls,...domains,...ips].slice(0,10).join(', ')||'No embedded network indicator observed'}</span></div><div><b>Persistence clues</b><span>${keywords.filter(x=>/schtasks|run|startup|registry/i.test(x)).join(', ')||'Not observed'}</span></div><div><b>Defense evasion clues</b><span>${keywords.filter(x=>/certutil|bitsadmin|base64|invoke-expression/i.test(x)).join(', ')||'Not observed'}</span></div></div>`)}${card('Observed network callbacks',`${[...urls,...domains,...ips].slice(0,100).map(x=>`<div class="forensic-row"><b>Indicator</b><span>${esc(x)}</span><small>Passive/static observation</small></div>`).join('')||'<div class="muted-box">No callback indicators recovered.</div>'}`)}`,
      narrative:`${card('AI-assisted threat narrative',`<div class="ir-warning">The narrative is constrained to evidence present in this case. Actor attribution, country, motivation and campaign identity remain hypotheses unless corroborated by independent intelligence sources.</div><div class="narrative">${esc(`File ${f.filename||'unknown'} is prioritized at ${f.risk}/100 based on static characteristics including ${keywords.length} suspicious keyword signal(s), entropy ${f.entropy??'unknown'}, and ${Object.values(inds).flat().length} embedded indicator(s). The observed evidence supports further investigation but does not by itself prove execution or attribution.`)}</div>`)}${card('MITRE ATT&CK candidate mapping',safeArray(state.result?.mitre_techniques).slice(0,100).map(x=>`<div class="mitre-row"><b>${esc(x.technique_id||x.id||'candidate')}</b><span>${esc(x.name||x.technique||'')}</span><small>${esc(x.reason||x.evidence||'')}</small></div>`).join('')||'<div class="muted-box">No ATT&CK candidates mapped.</div>')}${card('Campaign / attribution worksheet',`<div class="attribution-grid"><div><b>Observed facts</b><textarea>${esc((keywords.concat(urls.slice(0,10))).join('\n'))}</textarea></div><div><b>Hypothesis / confidence</b><textarea placeholder="Record actor or campaign hypothesis only with supporting sources and counter-evidence."></textarea></div></div>`)}`,
      action:`${card('Action & integration',`<div class="export-grid ir-action-grid"><button type="button" class="primary" data-ir-export="csv">Export IOC CSV</button><button type="button" class="secondary export" data-ir-export="sigma">Generate Sigma</button><button type="button" class="secondary export" data-ir-export="suricata">Generate Suricata</button><button type="button" class="secondary export" data-file-dossier-json="1">Download Dossier JSON</button></div><p class="muted">Review generated detections before deployment. Rules are generated from observed indicators, not inferred attribution.</p>`)}${card('Hunt for similar files',`<div class="metrics">${metric('SHA-256',h.sha256||f.sha256||'not available')}${metric('Fuzzy hash','Not calculated','connector/engine extension')}${metric('YARA','Not configured','signature engine extension')}${metric('Similar cases','Case-local only','cross-case search requires indexed corpus')}</div><p class="muted">Use the exact SHA-256 above as the strongest deterministic pivot. Similarity engines can be attached without changing this evidence model.</p>`)}${card('Artifact package',`<div class="stage-grid"><div><b>Original file</b><span>Available only when preserved by the evidence store.</span></div><div><b>Deobfuscated code</b><span>Not generated unless a safe static transformation is available.</span></div><div><b>YARA results</b><span>Signature connector status is shown explicitly.</span></div><div><b>PCAP snippet</b><span>Use the bounded packet workstation for packet evidence.</span></div></div>`)}`
    };
    const tabs=Object.entries({provenance:'Network Provenance',static:'Static & Code',behavior:'Behavioral / Sandbox',narrative:'AI Threat Narrative',action:'Action & Integration'}).map(([id,label],i)=>tab(id,label,panels[id],i===0)).join('');
    return `<div class="file-dossier" data-file-index="${f.index}"><header class="file-dossier-head"><div><div class="file-logo-line"><span class="k4-dossier-logo">K4</span><div><span class="network-eyebrow">K4 FORENSIC FILE DOSSIER</span><h2>${esc(f.filename||'Unknown artifact')}</h2><p>${esc(f.type||f.kind||'unknown')} · ${fmtBytes(f.size_bytes||f.size||0)} · risk ${f.risk}/100</p></div></div></div><button type="button" class="secondary" data-close-inspector>Close</button></header><div class="file-tabs">${tabs}</div><div class="file-panel" id="file-panel">${panels[activeTab]||panels.provenance}</div></div>`;
  }
  function fileRowHtml(f){
    const ctx=fileContext(f);
    return `<tr data-file-row="${f.index}" class="risk-row-${f.risk>=80?'critical':f.risk>=60?'high':f.risk>=30?'review':'low'}"><td><span class="risk-score risk-${f.risk>=80?'critical':f.risk>=60?'high':f.risk>=30?'review':'low'}">${f.risk}/100</span></td><td><b>${esc(f.filename||`file-${f.index+1}`)}</b><small>${esc(f.id||'')}</small></td><td>${badge(f.type||f.kind||'unknown',f.suspicious_extension?'bad':'')}<small>${esc(f.mime||'')}</small></td><td><small>Source: ${esc(ctx.sources.join(', ')||f.source||'not observed')}</small><small>Victim: ${esc(ctx.victims.join(', ')||'not observed')}</small></td><td><small>${esc(ctx.timestamp)}</small><small>Stream: ${esc(f.source_stream||'—')} · Offset: ${esc(f.offset??'—')}</small></td><td><code>${esc((f.hashes?.sha256||f.sha256||'').slice(0,18))}…</code></td><td>${esc(keywordsSummary(f))}</td><td><button type="button" class="primary file-open" data-file-index="${f.index}">Deep Dossier</button></td></tr>`;
  }
  function fileAnalysisView() {
    const all=normalizedFileRows(); const total=all.length; const critical=all.filter(x=>x.risk>=80).length;
    const suspicious=all.filter(x=>x.risk>=60).slice(0,12);
    return `<div class="stack">${card('Master File Analysis / Triage View',`<div class="ir-hero"><div><div class="file-logo-line"><span class="k4-dossier-logo">K4</span><div><span class="network-eyebrow">MASTER FILE ANALYSIS FLOW</span><h2>Artifact triage → deep dossier → response</h2><p>Every recovered file is scored for prioritization, sortable by evidence, and pivotable into a five-tab forensic dossier. The scoring is heuristic and never substitutes for analyst validation.</p></div></div></div><div class="ir-case-state"><strong>${critical}</strong><span>priority files ≥80</span></div></div>`)}${card('Priority suspicious-file queue',`<div class="suspicious-queue">${suspicious.map((f,i)=>`<button type="button" class="suspicious-file-card" data-file-index="${f.index}"><span class="queue-rank">${i+1}</span><div><b>${esc(f.filename||'artifact')}</b><small>${esc(f.type||f.kind||'unknown')} · ${fmtBytes(f.size_bytes||f.size||0)} · ${esc(f.source||f.source_stream||'')}</small><p>${esc(keywordsSummary(f))}</p></div><strong>${f.risk}/100</strong></button>`).join('')||'<div class="muted-box">No file reached the suspicious-candidate threshold. Review the full inventory for lower-confidence artifacts.</div>'}</div><p class="muted">Suspicious means high-priority static triage. It is not a malware verdict.</p>`)}${card('AI auto-triage & inventory controls',`<div class="file-controls"><label>Search <input id="file-search" placeholder="filename, hash, type, keyword…"></label><label>Risk <select id="file-risk-filter"><option value="all">All files</option><option value="critical">Critical ≥80</option><option value="high">High 60–79</option><option value="review">Review 30–59</option><option value="low">Low &lt;30</option></select></label><label>Sort <select id="file-sort"><option value="risk">Risk (high → low)</option><option value="name">Filename</option><option value="size">Size</option><option value="entropy">Entropy</option></select></label></div><div class="metrics">${metric('Extracted / analyzed',total,'bounded inventory')}${metric('Critical triage',critical,'heuristic priority')}${metric('High entropy',all.filter(x=>Number(x.entropy||0)>=7).length,'packing/encryption candidate')}${metric('Suspicious extension',all.filter(x=>x.suspicious_extension).length,'static heuristic')}</div>`)}${card('Risk heatmap / artifact inventory',`<div class="table-wrap"><table class="file-triage-table"><thead><tr><th>Risk</th><th>Filename</th><th>Type / MIME</th><th>Network context</th><th>Time / Stream</th><th>Hashes</th><th>AI triage summary</th><th>Action</th></tr></thead><tbody id="file-triage-body">${all.slice(0,500).map(fileRowHtml).join('')||'<tr><td colspan="8">No file candidates.</td></tr>'}</tbody></table></div>`)}${card('Triage methodology',`<div class="stage-grid"><div><b>Deterministic identity</b><span>SHA-256 / SHA-1 / MD5 where available.</span></div><div><b>Static risk</b><span>Entropy, type mismatch, extensions, suspicious keywords and indicators.</span></div><div><b>Network context</b><span>Source stream, offsets and matching normalized observations.</span></div><div><b>Human validation</b><span>Analyst opens the dossier before declaring maliciousness.</span></div></div>`)}</div>`;
  }
  function keywordsSummary(f){
    const k=safeArray(f.suspicious_keywords), ind=Object.values(f.indicators||{}).flat();
    if(k.length)return `Static signals: ${k.slice(0,4).join(', ')}${k.length>4?'…':''}`;
    if(ind.length)return `${ind.length} embedded indicator(s) observed`;
    if(Number(f.entropy||0)>=7)return 'High entropy; inspect packing/encryption possibility';
    return 'No high-priority static signal observed';
  }

  function toolchainView(){
    const rows=safeArray(state.toolchain?.tools);
    const summary=state.toolchain?.summary||{};
    return `<div class="stack">${card('K4 Open-source Analyst Toolchain',`<div class="ir-hero"><div><div class="file-logo-line"><span class="k4-dossier-logo">K4</span><div><span class="network-eyebrow">ANALYST TOOLCHAIN / READ-ONLY ADAPTER REGISTRY</span><h2>584 adapter entries across 100+ analyst projects and components</h2><p>Detects installed binaries and exposes connector slots without silently executing third-party software. The PCAP pipeline remains passive by default.</p></div></div></div><div class="ir-case-state"><strong>${esc(summary.open_source_count||0)}</strong><span>cataloged OSS/community entries</span></div></div>`)}${card('Toolchain health',`<div class="metrics">${metric('Catalog entries',summary.tool_count||rows.length,'adapters/components')}${metric('Open-source/community',summary.open_source_count||0,'cataloged')}${metric('Installed here',summary.installed_count||0,'binary detected')}${metric('Connector slots',summary.connector_count||0,'external integration')}</div><p class="muted">${esc(summary.execution_policy||'Adapters are opt-in and read-only by default.')}</p>`)}${card('Search and filter',`<div class="file-controls"><label>Search <input id="tool-search" placeholder="Wireshark, Zeek, YARA, Velociraptor…"></label><label>Category <select id="tool-category"><option value="all">All categories</option>${safeArray(summary.categories).map(c=>`<option value="${esc(c)}">${esc(c)}</option>`).join('')}</select></label><label>Status <select id="tool-status"><option value="all">All</option><option value="ready">Installed / ready</option><option value="not_installed">Not installed</option><option value="connector">Connector</option></select></label></div>`)}${card('Integrated analyst ecosystem',`<div class="table-wrap"><table class="tool-table"><thead><tr><th>Tool / Project</th><th>Category</th><th>Purpose</th><th>Mode</th><th>OSS</th><th>Runtime</th><th>Executable</th></tr></thead><tbody id="toolchain-body"></tbody></table></div>`)}${card('Integration architecture',`<div class="stage-grid"><div><b>PCAP / PCAPNG</b><span>Wireshark/TShark, Zeek, Suricata, Arkime, flow analyzers and parser adapters.</span></div><div><b>Recovered files</b><span>YARA, capa, FLOSS, file/metadata, PE/Office/PDF, carving and hashing adapters.</span></div><div><b>Endpoint pivots</b><span>Velociraptor, osquery, GRR, Hayabusa, Chainsaw, Plaso and artifact parsers.</span></div><div><b>Threat intelligence</b><span>MISP, OpenCTI, TheHive/Cortex, STIX/TAXII and feed connectors.</span></div><div><b>Detection engineering</b><span>Sigma, YARA, Suricata, Snort and Zeek rule ecosystems.</span></div><div><b>Evidence processing</b><span>jq, DuckDB, SQLite, Arrow/Parquet, Python and report/export adapters.</span></div></div><p class="muted">${esc(summary.license_note||'Verify each upstream project license before redistribution.')}</p>`)}</div>`;
  }
  function bindToolchain(){
    const search=document.getElementById('tool-search'), category=document.getElementById('tool-category'), status=document.getElementById('tool-status'), body=document.getElementById('toolchain-body');
    const renderTools=()=>{
      const q=(search?.value||'').toLowerCase(), c=category?.value||'all', st=status?.value||'all';
      const rows=safeArray(state.toolchain?.tools).filter(x=>{const hay=`${x.name} ${x.category} ${x.purpose} ${x.executable}`.toLowerCase();return (!q||hay.includes(q))&&(c==='all'||x.category===c)&&(st==='all'||x.status===st);}).slice(0,1000);
      if(body) body.innerHTML=rows.map(x=>`<tr class="tool-row"><td><b>${esc(x.name)}</b><small>${esc(x.source_kind||'project')}</small></td><td>${esc(x.category)}</td><td>${esc(x.purpose)}</td><td>${badge(x.mode||'offline',x.mode==='connector'?'warn':'')}</td><td>${x.open_source?badge('OSS','good'):badge('Reference','warn')}</td><td>${x.status==='ready'?badge('Ready','good'):x.status==='connector'?badge('Connector','warn'):badge('Not installed')}</td><td><code>${esc(x.executable||'—')}</code></td></tr>`).join('')||'<tr><td colspan="7">No matching adapters.</td></tr>';
    };
    search?.addEventListener('input',renderTools); category?.addEventListener('change',renderTools); status?.addEventListener('change',renderTools); renderTools();
  }

  function protocolView() {
    const p = state.result.protocol_analysis || {}; const tls = state.result.tls_analysis || {}; const cert = state.result.certificate_analysis || {}; const cipher = state.result.cipher_analysis || {};
    return `<div class="stack">
      ${card("Protocol distribution", `<div class="metrics">${Object.entries(p.protocol_counts||{}).slice(0,8).map(([k,v])=>metric(k,v,"normalized events")).join("")||metric("Protocols",0,"none")}</div>`)}
      <div class="grid2">${card("Top destination ports", `<div class="table-wrap"><table><thead><tr><th>Port</th><th>Observations</th></tr></thead><tbody>${Object.entries(p.top_destination_ports||{}).slice(0,50).map(([k,v])=>`<tr><td><code>${esc(k)}</code></td><td>${esc(v)}</td></tr>`).join("")||`<tr><td colspan="2">None</td></tr>`}</tbody></table></div>`)}${card("TLS analysis", `<pre>${esc(JSON.stringify(tls,null,2))}</pre><h4>Certificate analysis</h4><pre>${esc(JSON.stringify(cert,null,2))}</pre><h4>Cipher analysis</h4><pre>${esc(JSON.stringify(cipher,null,2))}</pre>`)}</div>
      ${card("PCAP deep-capture summary", `<pre>${esc(JSON.stringify(p.pcap||{},null,2))}</pre>`)}
    </div>`;
  }

  function hostView() {
    const hosts=state.result.asset_profiles||[]; const victims=state.result.victim_profiles||[]; const external=state.result.external_sources||[];
    return `<div class="stack">${card("Asset inventory", `<div class="table-wrap"><table><thead><tr><th>IP</th><th>Bytes</th><th>Peers</th><th>Top ports</th><th>Protocols</th></tr></thead><tbody>${hosts.slice(0,500).map(h=>`<tr><td><code>${esc(h.ip)}</code></td><td>${esc(h.bytes)}</td><td>${esc(h.peer_count)}</td><td>${esc(Object.keys(h.top_ports||{}).slice(0,12).join(", "))}</td><td>${esc(Object.keys(h.protocols||{}).join(", "))}</td></tr>`).join("")||`<tr><td colspan="5">No asset profiles.</td></tr>`}</tbody></table></div>`)}${card("Victim / host identity observations", victims.slice(0,200).map(v=>`<details><summary>${esc(v.ip)} · ${esc((v.hostnames||[]).join(", ")||"hostname unavailable")}</summary><pre>${esc(JSON.stringify(v,null,2))}</pre></details>`).join("")||`<div class="muted-box">No identity observations.</div>`)}${card("External source candidates", external.slice(0,200).map(v=>`<div class="finding-row"><div><b>${esc(v.source_ip)}</b><p>${esc(v.connections)} observed connection(s) to ${esc((v.internal_targets||[]).join(", "))}</p></div>${badge("candidate")}</div>`).join("")||`<div class="muted-box">No external-source candidates.</div>`)}</div>`;
  }

  function storyView() {
    const b=state.result.behavioral_analysis||{}; const assessment=state.result.network_assessment||{};
    const sections=[['Beaconing / C2 candidates',b.beaconing_candidates],['DNS tunneling candidates',b.dns_tunneling_candidates],['DGA-like domains',b.dga_candidates],['Lateral movement',b.lateral_movement_candidates],['Exfiltration candidates',b.exfiltration_candidates],['Port / host scanning',b.scan_candidates]];
    const summaryRows=sections.map(([name,items],i)=>`<div><i>${i+1}</i><span><b>${esc(name)}</b> — ${esc((items||[]).length)} candidate(s)</span></div>`).join("");
    const detailCards=sections.map(([name,items])=>{
      const body=(items||[]).slice(0,100).map(x=>`<details><summary>${esc(x.source||x.domain||x.destination||x.name||"candidate")} · confidence ${esc(x.confidence??"—")}</summary><pre>${esc(JSON.stringify(x,null,2))}</pre></details>`).join("") || `<div class="muted-box">No candidates.</div>`;
      return card(name,body);
    }).join("");
    return `<div class="stack">${card("Attacker behaviour reconstruction", `<p class="muted">This is an evidence-led reconstruction of observable behaviour. It does not identify a person or prove compromise. Each hypothesis should be corroborated with independent telemetry.</p><div class="pipeline-list">${summaryRows}</div>`)}${detailCards}${card("Network assessment", `<pre>${esc(JSON.stringify(assessment,null,2))}</pre>`)}</div>`;
  }

  function incidentView() {
    const ir=state.result?.incident_response||{}; const iocs=state.result?.iocs||{}; const r=state.result||{};
    const executive=(r.narrative||'').split(/\n+/).filter(Boolean).slice(0,3).join(' ');
    const counts=Object.values(iocs).reduce((n,v)=>n+safeArray(v).length,0);
    return `<div class="stack"><div class="ir-hero"><div><span class="network-eyebrow">INCIDENT RESPONSE / ACTION CENTER</span><h2>Contain, preserve, eradicate, recover</h2><p>Turn evidence into controlled response actions. Every action remains traceable to an observation, indicator or analyst decision.</p></div><div class="ir-case-state">${badge('evidence preserved','good')}<strong>${counts}</strong><span>IOC records available for blocking</span></div></div>
      ${card('Response lifecycle',(ir.phases||[]).map((p,i)=>`<div class="finding-row"><div><div class="finding-title"><b>${esc(p.phase)}</b>${badge(p.status||'analysis_output')}</div><p>${esc(p.purpose)}</p></div><span>${i+1}</span></div>`).join('')||'<div class="muted-box">No IR workflow generated.</div>')}
      ${card('Blocklist generator',`<div class="export-grid ir-action-grid"><button class="primary" type="button" data-ir-export="csv">IOC CSV</button><button class="secondary export" type="button" data-ir-export="sigma">Sigma rules</button><button class="secondary export" type="button" data-ir-export="snort">Snort rules</button><button class="secondary export" type="button" data-ir-export="suricata">Suricata rules</button></div><p class="muted">Generated from observed IOCs only. Review before deployment to production controls.</p>`)}
      ${card('Executive summary',`<div class="narrative">${esc(executive||'No narrative available. Use the report generator after corroboration.')}</div><div class="ir-approval"><label>Analyst disposition <select id="ir-disposition"><option>Needs corroboration</option><option>Confirmed malicious activity</option><option>Benign / expected activity</option><option>Insufficient evidence</option></select></label><textarea id="ir-analyst-note" placeholder="Record the decision, supporting evidence, and counter-evidence."></textarea><button type="button" class="primary" id="ir-save-note">Save analyst note locally</button><span id="ir-note-status" class="muted"></span></div>`)}
      ${card('Evidence preservation',`<pre>${esc(JSON.stringify(ir.evidence_preservation||{},null,2))}</pre>`)}
      ${card('Follow-up collection plan',(ir.follow_up_evidence||[]).map(x=>`<details><summary>${esc(x.finding||'Finding')} · ${esc(x.priority||'')}</summary><p class="muted">${esc(x.next_collection||'')}</p></details>`).join('')||'<div class="muted-box">No finding-specific follow-up actions.</div>')}
    </div>`;
  }
  function makeBlocklist(kind){
    const i=state.result?.iocs||{}; const ips=safeArray(i.ip), domains=safeArray(i.domain||i.domains), hashes=safeArray(i.sha256||i.hash);
    if(kind==='csv'){ return ['type,value',...ips.map(x=>`ip,${x}`),...domains.map(x=>`domain,${x}`),...hashes.map(x=>`sha256,${x}`)].join('\n'); }
    if(kind==='sigma'){ return ['title: K4 Network Investigation IOC Rules','status: experimental','logsource:','  category: network_connection','detection:','  selection:','    dst_ip: ['+ips.map(x=>JSON.stringify(x)).join(', ')+']','  condition: selection','level: high',''].join('\n'); }
    if(kind==='snort'||kind==='suricata'){ const rules=[];ips.forEach((ip,n)=>rules.push(`alert ip any any -> ${ip} any (msg:"K4 IR observed IOC ${ip}"; sid:420000${n+1}; rev:1;)`));domains.slice(0,100).forEach((d,n)=>rules.push(`alert http any any -> any any (msg:"K4 IR observed domain ${d}"; content:"${String(d).replace(/"/g,'\\"')}"; nocase; sid:421000${n+1}; rev:1;)`)); return rules.join('\n')+'\n'; }
    return '';
  }
  function downloadTextFile(name,text,type='text/plain'){ const blob=new Blob([text],{type}); const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url); }
  async function openPacketWorkbench(filter=''){
    if(!state.job?.job_id){openInspector('Packet Workstation','<div class="muted-box">Complete an investigation first.</div>');return;}
    try{
      const q=new URLSearchParams({limit:'120'}); if(filter)q.set('filter_text',filter); if(state.job.access_key)q.set('access_key',state.job.access_key);
      const data=await api(`/jobs/${encodeURIComponent(state.job.job_id)}/packets?${q.toString()}`);
      const rows=safeArray(data.packets);
      const packet=rows[0];
      openInspector('Embedded Packet Workstation',`${card('Packet list',`<div class="packet-list">${rows.map((x,i)=>`<button type="button" data-packet-index="${i}"><b>#${esc(x.packet_index)}</b><span>${esc(x.src_ip||'')} → ${esc(x.dst_ip||'')}</span><small>${esc(x.protocol||'')} · ${esc(x.length)} bytes · ${esc(x.timestamp||'')}</small></button>`).join('')||'<div class="muted-box">No packets matched.</div>'}</div>`)}${packet?`<div class="packet-three"><section><h4>Packet metadata</h4><pre>${esc(JSON.stringify({...packet,hex_preview:undefined},null,2))}</pre></section><section><h4>Protocol tree</h4><pre>${esc(JSON.stringify({protocol:packet.protocol,tcp_flags:packet.tcp_flags,dns:packet.dns,http:packet.http,tls_sni:packet.tls_sni},null,2))}</pre></section><section><h4>Hex dump</h4><pre class="hex-dump">${esc(packet.hex_preview||'')}</pre></section></div>`:''}`);
      document.querySelectorAll('[data-packet-index]').forEach(el=>el.addEventListener('click',()=>{const x=rows[Number(el.dataset.packetIndex)];if(x)openInspector(`Packet #${x.packet_index}`,`<div class="packet-three"><section><h4>Packet metadata</h4><pre>${esc(JSON.stringify({...x,hex_preview:undefined},null,2))}</pre></section><section><h4>Protocol tree</h4><pre>${esc(JSON.stringify({protocol:x.protocol,tcp_flags:x.tcp_flags,dns:x.dns,http:x.http,tls_sni:x.tls_sni},null,2))}</pre></section><section><h4>Hex dump</h4><pre class="hex-dump">${esc(x.hex_preview||'')}</pre></section></div>`);}));
    }catch(error){openInspector('Packet Workstation Error',`<div class="error">${esc(error.message||'Packet drill-down failed')}</div>`);}
  }

  function iocView() {
    const iocs = state.result.iocs || {};
    const sections = Object.entries(iocs).map(([kind, values]) => card(kind, (values || []).slice(0, 1000).map((value) => `<div class="ioc-line"><code>${esc(value)}</code><button type="button" data-copy-ioc="${esc(value)}">Copy</button></div>`).join("") || `<span class="muted">No indicators extracted.</span>`));
    return `<div class="grid2">${sections.join("") || emptyView("No IOCs", "No indicators were extracted.")}</div>`;
  }

  function timelineView() {
    const events = state.result.network_timeline || state.result.timeline || [];
    return card("Unified network timeline", `<div class="timeline">${events.slice(0, 1000).map((event, index) => `<div class="time-row"><span>${esc(event.timestamp || "timestamp unavailable")}</span><b>${esc(event.event_type || "event")}</b><small>${esc(event.source || "")}</small><p>${esc(event.src_ip || "")} ${event.dst_ip ? `→ ${esc(event.dst_ip)}` : ""} ${esc(event.message || "")}</p><em>EV-${String(index + 1).padStart(5, "0")}</em></div>`).join("") || `<div class="muted-box">No timeline events.</div>`}</div>`);
  }

  function graphView() {
    const graph = state.result.network_graph || { nodes: [], edges: [] };
    const nodes = (graph.nodes || []).slice(0, 100);
    const edges = (graph.edges || []).slice(0, 160);
    const positions = new Map(nodes.map((node, index) => [node.id, { x: (index % 12) * 82 + 60, y: 70 + (Math.floor(index / 12) % 7) * 72 }]));
    const lines = edges.map((edge) => {
      const from = positions.get(edge.source);
      const to = positions.get(edge.target);
      if (!from || !to) return "";
      return `<line x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}" />`;
    }).join("");
    const circles = nodes.map((node) => {
      const pos = positions.get(node.id);
      const publicNode = node.scope === "public";
      return `<g><circle cx="${pos.x}" cy="${pos.y}" r="19" class="${publicNode ? "public" : "private"}"/><text x="${pos.x}" y="${pos.y + 4}" text-anchor="middle">${esc(String(node.id).slice(-8))}</text><title>${esc(node.id)}</title></g>`;
    }).join("");
    return card(`Network graph — ${nodes.length} displayed / ${graph.nodes?.length || 0} total nodes`, `<div class="graph"><svg viewBox="0 0 1040 580" role="img" aria-label="Network relationship graph">${lines}${circles}</svg></div><p class="muted">Graph edges represent observed source/destination relationships; they do not prove compromise or attribution.</p>`);
  }

  function findingRow(finding) {
    const tone = finding.severity === "high" ? "bad" : finding.severity === "medium" ? "warn" : "";
    return `<div class="finding-row"><div><div class="finding-title"><b>${esc(finding.name || "Finding")}</b>${badge(finding.severity || "info", tone)}</div><p>${esc(finding.reason || "")}</p><small>Confidence: ${esc(finding.confidence ?? "—")} · Score: ${esc(finding.score ?? "0")}</small></div><details><summary>Evidence</summary><pre>${esc(JSON.stringify(finding.evidence || {}, null, 2))}</pre></details></div>`;
  }

  function findingsView() {
    const findings = state.result.findings || [];
    return `<div class="stack">${card("Behavioral findings", findings.map(findingRow).join("") || `<div class="muted-box">No findings generated.</div>`)}${card("MITRE ATT&CK observations", (state.result.mitre_techniques || []).map((item) => `<div class="mitre-row"><b>${esc(item.technique_id || item.id || "Unknown")}</b><span>${esc(item.name || item.technique || "")}</span><small>${esc(item.reason || item.evidence || "")}</small></div>`).join("") || `<div class="muted-box">No supported ATT&CK mapping was produced.</div>`)}</div>`;
  }

  function evidenceView() {
    const events = state.result.raw_evidence?.events || [];
    return card("Raw evidence locker", `<p class="muted">Showing up to 300 normalized evidence records from the investigation result.</p><div class="evidence-grid">${events.slice(0, 300).map((event, index) => `<details><summary>EV-${String(index + 1).padStart(5, "0")} · ${esc(event.event_type || event.source || "artifact")} · ${esc(event.timestamp || "no timestamp")}</summary><pre>${esc(JSON.stringify(event, null, 2))}</pre></details>`).join("") || `<div class="muted-box">No raw evidence records.</div>`}</div>`);
  }

  function agentView() {
    return `<div class="stack">${card('K4 Investigation Agent',`<p class="muted">Ask evidence-grounded questions about this completed case. The agent searches normalized observations, findings, files, behavioral candidates and IOC context. It never executes uploaded payloads or performs active scanning.</p><form id="agent-form" class="agent-form"><textarea id="agent-question" rows="4" placeholder="Example: show me all suspicious files, what hosts communicated with 10.1.21.101, or what evidence supports beaconing?"></textarea><button type="submit" class="primary">Investigate evidence</button></form><div id="agent-status" class="muted"></div>`)}${card('Agent result',`<div id="agent-result" class="agent-result"><div class="muted-box">Ask a question to populate evidence and pivots.</div></div>`)}${card('Agent guardrails',`<div class="checklist"><label><input type="checkbox" checked disabled><span>Passive evidence analysis only</span></label><label><input type="checkbox" checked disabled><span>No uploaded payload execution</span></label><label><input type="checkbox" checked disabled><span>No active network scanning</span></label><label><input type="checkbox" checked disabled><span>No unsupported attribution</span></label></div>`)}</div>`;
  }

  function reportView() {
    const formats = [
      ["html", "HTML Report"],
      ["pdf", "PDF Report"],
      ["json", "JSON Evidence"],
      ["ioc-csv", "IOC CSV"],
      ["events-csv", "Events CSV"],
      ["stix", "STIX Bundle"],
    ];
    return `<div class="stack">
      ${card("Investigation report", `<div class="report-head"><div><span>Network Artifacts Investigation</span><h2>${esc(state.result.verdict || "unknown")}</h2><p class="muted">Generated from passive network evidence. Live threat-intelligence connectors remain clearly marked when not configured.</p></div><div class="score">${esc(state.result.risk_score ?? 0)}<small>/100</small></div></div>`)}
      ${card("Export", `<div class="export-grid">${formats.map(([format, label]) => `<button type="button" class="secondary export" data-format="${format}">${esc(label)}</button>`).join("")}</div><div id="export-message" class="muted"></div>`)}
      ${card("Threat intelligence ledger", `<div class="table-wrap"><table><thead><tr><th>IOC</th><th>Status</th><th>Reason</th></tr></thead><tbody>${Object.entries(state.result.threat_intel_ledger || {}).slice(0, 200).map(([key, item]) => `<tr><td><code>${esc(item.ioc || key)}</code></td><td>${badge(item.status || "unknown")}</td><td>${esc(item.reason || "")}</td></tr>`).join("") || `<tr><td colspan="3">No enrichment ledger entries.</td></tr>`}</tbody></table></div>`)}
      <div class="report-actions"><button type="button" class="primary" id="save-job">Save / sync to my account</button><span class="muted">Saving requires an authenticated account.</span></div>
    </div>`;
  }

  function bindDynamicActions() {
    document.querySelectorAll("[data-copy-ioc]").forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(button.dataset.copyIoc || "");
          button.textContent = "Copied";
          window.setTimeout(() => { button.textContent = "Copy"; }, 900);
        } catch (_) {
          button.textContent = "Copy failed";
        }
      });
    });

    document.querySelectorAll("[data-format]").forEach((button) => {
      button.addEventListener("click", () => downloadReport(button.dataset.format));
    });

    document.querySelectorAll('[data-close-inspector]').forEach(x=>x.addEventListener('click',()=>{const m=document.getElementById('ir-inspector');if(m)m.hidden=true;document.body.classList.remove('ir-modal-open');}));
    document.querySelectorAll('[data-node]').forEach(el=>el.addEventListener('click',()=>{const n=graphNode(el.dataset.node);if(!n)return;const related=safeArray(state.result?.network_graph?.edges).filter(e=>String(e.source)===String(n.id)||String(e.target)===String(n.id));openInspector('Threat / Asset Dossier',`<div class="drawer-grid">${metric('Entity',n.id||'unknown')}${metric('Scope',n.scope||'unknown')}${metric('Type',n.type||'observed')}${metric('Relationships',related.length)}</div>${card('Evidence profile',inspectorObject(n))}${card('Observed connections',related.slice(0,100).map(e=>`<div class="forensic-row"><b>${esc(e.source)}</b><span>→ ${esc(e.target)}</span><small>${esc(e.protocol||e.label||'relationship')} · ${fmtBytes(e.bytes||0)} · ${esc(e.first_seen||'')}</small></div>`).join('')||'<div class="muted-box">No related edges.</div>')}`);}));
    document.querySelectorAll('[data-edge]').forEach(el=>el.addEventListener('click',()=>{const e=graphEdge(el.dataset.edge);if(!e)return;openInspector('Connection Details',`<div class="drawer-grid">${metric('Source',e.source||'unknown')}${metric('Destination',e.target||'unknown')}${metric('Protocol',e.protocol||e.label||'unknown')}${metric('Bytes',fmtBytes(e.bytes||0))}</div>${card('Connection evidence',inspectorObject(e))}<button type="button" class="primary" data-tab="packets">View raw packet workspace</button>`);}));
    document.querySelectorAll('[data-event-id]').forEach(el=>el.addEventListener('click',()=>{const e=eventById(el.dataset.eventId);if(!e)return;openInspector('Timeline Evidence',`${card('Event detail',inspectorObject(e))}<div class="hero-actions"><button type="button" class="primary" data-tab="packets">View Raw Packets</button><button type="button" class="secondary" data-tab="evidence">Open Evidence Locker</button></div>`);}));
    document.querySelectorAll('[data-host-index]').forEach(el=>el.addEventListener('click',()=>{const hosts=safeArray(state.result?.victim_profiles).length?safeArray(state.result?.victim_profiles):safeArray(state.result?.asset_profiles);const h=hosts[Number(el.dataset.hostIndex)];if(h)openInspector('Victim / Endpoint Profile',hostProfileDetail(h));}));
    document.querySelectorAll('.packet-detail').forEach(el=>el.addEventListener('click',()=>{const c=safeArray(state.result?.protocol_analysis?.pcap?.conversations)[Number(el.dataset.convIndex)];if(c)openPacketWorkbench(`${c.src_ip||''} ${c.dst_ip||''} ${c.src_port||''} ${c.dst_port||''}`);}));
    document.querySelectorAll('.forensic-row').forEach(el=>el.addEventListener('click',()=>{const idx=Number(el.dataset.beaconIndex);const x=safeArray(state.result?.behavioral_analysis?.beaconing_candidates)[idx];if(x)openInspector('Beaconing Evidence',`${card('Candidate',inspectorObject(x))}${card('Analyst validation',`<div class="checklist"><label><input type="checkbox"> <span>Regularity corroborated across independent observations</span></label><label><input type="checkbox"> <span>DNS/TLS sequence corroborates destination</span></label><label><input type="checkbox"> <span>Endpoint telemetry corroborates process ownership</span></label></div>`)}`);}));
    document.querySelectorAll('[data-ir-export]').forEach(el=>el.addEventListener('click',()=>{const kind=el.dataset.irExport;const ext=kind==='csv'?'csv':kind==='sigma'?'yml':kind==='suricata'?'rules':'rules';downloadTextFile(`k4-ir-blocklist-${kind}.${ext}`,makeBlocklist(kind),kind==='csv'?'text/csv':'text/plain');}));
    document.querySelectorAll('[data-file-dossier-json]').forEach(el=>el.addEventListener('click',()=>{const d=el.closest('.file-dossier');const f=normalizedFileRows()[Number(d?.dataset.fileIndex||0)];if(f)downloadTextFile(`k4-file-dossier-${String(f.filename||'artifact').replace(/[^a-z0-9._-]/gi,'_')}.json`,JSON.stringify(f,null,2),'application/json');}));
    const note=document.getElementById('ir-save-note'); if(note) note.addEventListener('click',()=>{const value={disposition:document.getElementById('ir-disposition')?.value||'',note:document.getElementById('ir-analyst-note')?.value||'',saved_at:new Date().toISOString()};localStorage.setItem(`k4-ir-note-${state.job?.job_id||'draft'}`,JSON.stringify(value));const status=document.getElementById('ir-note-status');if(status)status.textContent='Saved locally for this browser session.';});
    document.querySelectorAll('.file-open').forEach(el=>el.addEventListener('click',()=>{const f=normalizedFileRows()[Number(el.dataset.fileIndex)];if(f)openInspector('K4 Deep File Dossier',fileDossier(f));}));
    document.querySelectorAll('.suspicious-file-card').forEach(el=>el.addEventListener('click',()=>{const f=normalizedFileRows()[Number(el.dataset.fileIndex)];if(f)openInspector('K4 Deep File Dossier',fileDossier(f));}));
    document.querySelectorAll('[data-file-tab]').forEach(el=>el.addEventListener('click',()=>{const panel=document.getElementById('file-panel');if(!panel)return;const dossierEl=el.closest('.file-dossier');if(!dossierEl)return;const fileIndex=Number(dossierEl.dataset.fileIndex||0);const f=normalizedFileRows()[fileIndex];if(!f)return;const wrapper=document.createElement('div');wrapper.innerHTML=fileDossier(f,el.dataset.fileTab);const inner=wrapper.querySelector('.file-panel');panel.innerHTML=inner?inner.innerHTML:panel.innerHTML;}));
    const fileSearch=document.getElementById('file-search'); const fileRisk=document.getElementById('file-risk-filter'); const fileSort=document.getElementById('file-sort');
    if(fileSearch||fileRisk||fileSort){const refreshFiles=()=>{const q=(fileSearch?.value||'').toLowerCase();const risk=fileRisk?.value||'all';const sort=fileSort?.value||'risk';let rows=normalizedFileRows().filter(f=>{const hay=JSON.stringify(f).toLowerCase();const passQ=!q||hay.includes(q);const passR=risk==='all'||(risk==='critical'&&f.risk>=80)||(risk==='high'&&f.risk>=60&&f.risk<80)||(risk==='review'&&f.risk>=30&&f.risk<60)||(risk==='low'&&f.risk<30);return passQ&&passR;});rows.sort((a,b)=>sort==='name'?String(a.filename||'').localeCompare(String(b.filename||'')):sort==='size'?Number(b.size_bytes||b.size||0)-Number(a.size_bytes||a.size||0):sort==='entropy'?Number(b.entropy||0)-Number(a.entropy||0):b.risk-a.risk);const body=document.getElementById('file-triage-body');if(body)body.innerHTML=rows.slice(0,500).map(fileRowHtml).join('')||'<tr><td colspan="8">No files match the current filter.</td></tr>';document.querySelectorAll('.file-open').forEach(x=>x.addEventListener('click',()=>{const f=normalizedFileRows()[Number(x.dataset.fileIndex)];if(f)openInspector('K4 Deep File Dossier',fileDossier(f));}));document.querySelectorAll('.suspicious-file-card').forEach(x=>x.addEventListener('click',()=>{const f=normalizedFileRows()[Number(x.dataset.fileIndex)];if(f)openInspector('K4 Deep File Dossier',fileDossier(f));}));};fileSearch?.addEventListener('input',refreshFiles);fileRisk?.addEventListener('change',refreshFiles);fileSort?.addEventListener('change',refreshFiles);}
    const graphSearch=document.getElementById('graph-search'); const graphScope=document.getElementById('graph-scope'); if(graphSearch||graphScope){const filterGraph=()=>{const q=(graphSearch?.value||'').toLowerCase(),scope=graphScope?.value||'all';document.querySelectorAll('[data-node]').forEach(el=>{const n=graphNode(el.dataset.node);const visible=n&&(!q||JSON.stringify(n).toLowerCase().includes(q))&&(scope==='all'||String(n.scope||'')===scope);el.style.opacity=visible?'1':'0.12';});};graphSearch?.addEventListener('input',filterGraph);graphScope?.addEventListener('change',filterGraph);}
    const graphDensity=document.getElementById('graph-density'); const graphLayout=document.getElementById('graph-layout');
    graphDensity?.addEventListener('change',()=>{state.graphMax=Number(graphDensity.value)||180;render();});
    graphLayout?.addEventListener('change',()=>{state.graphLayout=graphLayout.value||'radial';render();});
    const packetSearch=document.getElementById('packet-search'); if(packetSearch) packetSearch.addEventListener('click',()=>openPacketWorkbench(document.getElementById('packet-filter')?.value||''));
    const save = document.getElementById("save-job");
    if (save) save.addEventListener("click", saveInvestigation);
    const agentForm=document.getElementById("agent-form");
    if(agentForm) agentForm.addEventListener("submit",async(event)=>{event.preventDefault();const q=document.getElementById("agent-question")?.value?.trim();const status=document.getElementById("agent-status");const out=document.getElementById("agent-result");if(!q||!state.job?.job_id){if(status)status.textContent="Enter a question after completing an investigation.";return;}if(status)status.textContent="Agent is searching the evidence graph…";try{const access=state.job.access_key?`&access_key=${encodeURIComponent(state.job.access_key)}`:'';const data=await api(`/jobs/${encodeURIComponent(state.job.job_id)}/agent/query?question=${encodeURIComponent(q)}${access}`,{method:'POST'});if(status)status.textContent=`Matched ${data.matched_events?.length||0} events and ${data.focused_evidence?.length||0} focused evidence records.`;if(out)out.innerHTML=`<div class="agent-answer"><p>${esc(data.answer||'')}</p><h4>Matched evidence</h4>${(data.matched_events||[]).slice(0,50).map(x=>`<details><summary>${esc(x.timestamp||x.indicator||x.event_type||'evidence')} · ${esc(x.src_ip||'')} ${x.dst_ip?`→ ${esc(x.dst_ip)}`:''}</summary><pre>${esc(JSON.stringify(x,null,2))}</pre></details>`).join('')||'<div class="muted-box">No direct matches.</div>'}<h4>Focused evidence</h4>${(data.focused_evidence||[]).slice(0,50).map(x=>`<details><summary>${esc(x.filename||x.name||x.domain||x.source||'candidate')}</summary><pre>${esc(JSON.stringify(x,null,2))}</pre></details>`).join('')||'<div class="muted-box">No focused evidence.</div>'}<h4>Suggested pivots</h4><div class="chips">${(data.suggested_pivots||[]).map(x=>{const map={network_graph:'graph',packet_level_forensics:'packets',incident_response:'incident',timeline:'timeline',files:'files',iocs:'iocs'};const tab=map[x]||x;return `<button type="button" class="secondary" data-tab="${esc(tab)}">${esc(x)}</button>`;}).join('')}</div></div>`;}catch(error){if(status)status.textContent=error.message||'Agent query failed.';}});

  }

  async function downloadReport(format) {
    if (!state.job?.job_id) return;
    const message = document.getElementById("export-message");
    try {
      const token = csrf();
      const access = state.job?.access_key ? `?access_key=${encodeURIComponent(state.job.access_key)}` : "";
      const response = await fetch(`/api/v1/pcap/jobs/${encodeURIComponent(state.job.job_id)}/report/${encodeURIComponent(format)}${access}`, {
        credentials: "include",
        headers: token ? { "X-CSRF-Token": token } : {},
      });
      if (!response.ok) throw new Error((await response.text()) || response.statusText);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `network-artifacts-${state.job.job_id}.${format === "ioc-csv" ? "iocs.csv" : format === "events-csv" ? "events.csv" : format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      if (message) message.textContent = `${format.toUpperCase()} report generated.`;
    } catch (error) {
      if (message) message.textContent = error.message || "Report export failed.";
    }
  }

  async function saveInvestigation() {
    if (!state.job?.job_id) return;
    const button = document.getElementById("save-job");
    if (button) button.disabled = true;
    try {
      const response = await api(`/jobs/${encodeURIComponent(state.job.job_id)}/save`, { method: "POST" });
      setAlert(`Investigation saved as scan #${response.scan_id}.`);
    } catch (error) {
      setAlert(error.message || "Unable to save investigation. Sign in first if this is a guest session.");
    } finally {
      if (button) button.disabled = false;
    }
  }

  const originalRender = render;
  render = function wrappedRender() {
    try {
      originalRender();
      bindDynamicActions();
      if (state.job) jobbar();
      setAlert("");
    } catch (error) {
      const content = document.getElementById("content");
      if (content) {
        content.innerHTML = `<div class="fatal-error"><h2>This investigation view could not render</h2><p>${esc(error.message || error)}</p><button type="button" class="primary" data-tab="overview">Return to IR Command Center</button><button type="button" class="secondary" data-tab="upload">Open Evidence Intake</button></div>`;
      }
      console.error("K4 Network Artifacts render error", error);
    }
  };

  try {
    shell();
  } catch (error) {
    root.innerHTML = `<div class="fatal-error"><h2>Network Artifacts UI failed to initialize</h2><p>${esc(error.message || error)}</p><pre>${esc(error.stack || "")}</pre></div>`;
  }
})();
