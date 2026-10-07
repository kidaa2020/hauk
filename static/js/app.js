// ── State ──────────────────────────────────────────────────────────────────
const state = {
  socket: null,
  results: {},
  scanRunning: false,
  startTime: null,
  timerInterval: null,
  activeView: "scan",
  activeTab: "secrets",
  sevFilter: "all",
  reportDir: null,
};

// ── Socket.IO ──────────────────────────────────────────────────────────────
function initSocket() {
  state.socket = io();

  state.socket.on("connect",     () => log("[+] Connected to ReconHawk server", "success"));
  state.socket.on("disconnect",  () => log("[!] Disconnected", "warning"));

  state.socket.on("log_history", ({ lines }) => lines.forEach(l => appendLog(l)));

  state.socket.on("log", ({ msg }) => appendLog(msg));

  state.socket.on("status", ({ running, domain }) => {
    if (running) setRunning(domain);
  });

  state.socket.on("scan_started", ({ domain }) => {
    toast(`Scan started: ${domain}`, "info");
    setRunning(domain);
    clearTerminal(false);
    switchView("scan");
  });

  state.socket.on("partial_result", ({ key, data }) => {
    state.results[key] = data;
    if (state.activeView === "results") renderResults();
  });

  state.socket.on("scan_done", ({ domain, summary, report_dir }) => {
    state.reportDir = report_dir;
    setIdle();
    toast(`✅ Scan complete: ${domain}`, "success");
    updateSummaryCards(summary);
    renderResults();
    // Show report link
    const link = document.getElementById("link-html-report");
    link.classList.remove("hidden");
    // Find actual HTML report file
    fetch("/api/scans")
      .then(r => r.json())
      .then(scans => {
        const match = scans.find(s => s.domain === domain);
        if (match) {
          const htmlFile = match.file.replace(".json", ".html");
          link.href = `/report/${htmlFile}`;
        }
      });
    switchView("results");
  });

  state.socket.on("scan_error", ({ msg }) => {
    setIdle();
    toast(`❌ Error: ${msg}`, "error");
    log(`[ERROR] ${msg}`, "error");
  });

  state.socket.on("error", ({ msg }) => toast(msg, "error"));
}

// ── Views ──────────────────────────────────────────────────────────────────
function switchView(view) {
  state.activeView = view;
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.getElementById(`view-${view}`).classList.add("active");
  document.querySelectorAll(".nav-link").forEach(l => {
    l.classList.toggle("active", l.dataset.view === view);
  });
  if (view === "results") renderResults();
  if (view === "history") loadHistory();
}

document.querySelectorAll(".nav-link").forEach(link => {
  link.addEventListener("click", e => { e.preventDefault(); switchView(link.dataset.view); });
});

// ── Tabs ───────────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    state.activeTab = btn.dataset.tab;
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(t => t.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

// ── Module toggles ─────────────────────────────────────────────────────────
document.querySelectorAll(".toggle-card").forEach(card => {
  card.addEventListener("click", () => {
    const chk = card.querySelector("input[type=checkbox]");
    chk.checked = !chk.checked;
    card.classList.toggle("active", chk.checked);
  });
});

// ── Format buttons ─────────────────────────────────────────────────────────
document.querySelectorAll(".fmt-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".fmt-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
  });
});

// ── Severity filter chips ──────────────────────────────────────────────────
document.querySelectorAll("#sev-filters .chip").forEach(chip => {
  chip.addEventListener("click", () => {
    document.querySelectorAll("#sev-filters .chip").forEach(c => c.classList.remove("active"));
    chip.classList.add("active");
    state.sevFilter = chip.dataset.sev;
    renderSecrets();
  });
});

// ── Scan control ──────────────────────────────────────────────────────────
function startScan() {
  const domain = document.getElementById("inp-domain").value.trim();
  if (!domain) { toast("Enter a domain first", "error"); return; }

  const modCard = (mod) => document.querySelector(`.toggle-card[data-mod="${mod}"] input`).checked;
  const fmtBtn  = document.querySelector(".fmt-btn.active");

  const payload = {
    domain,
    output:          document.getElementById("inp-output").value || `reports/${domain}`,
    threads:         document.getElementById("inp-threads").value,
    timeout:         document.getElementById("inp-timeout").value,
    depth:           document.getElementById("inp-depth").value,
    wordlist:        document.getElementById("inp-wordlist").value,
    ports:           document.getElementById("inp-ports").value,
    passive:         modCard("passive"),
    format:          fmtBtn ? fmtBtn.dataset.fmt : "both",
    skip_subdomains: !modCard("subdomains"),
    skip_ports:      !modCard("ports"),
    skip_fuzz:       !modCard("fuzz"),
    skip_scrape:     !modCard("scrape"),
    skip_secrets:    !modCard("secrets"),
  };

  state.socket.emit("start_scan", payload);
}

function stopScan() {
  state.socket.emit("stop_scan");
  toast("Stop requested...", "info");
}

function setRunning(domain) {
  state.scanRunning = true;
  state.startTime = Date.now();
  document.getElementById("status-dot").className  = "status-dot running";
  document.getElementById("status-text").textContent = "Scanning";
  document.getElementById("btn-start").disabled = true;
  document.getElementById("btn-stop").classList.remove("hidden");
  document.getElementById("progress-bar").classList.remove("hidden");
  document.getElementById("progress-fill").style.width = "0%";
  document.getElementById("res-domain").textContent = domain;
  state.timerInterval = setInterval(updateTimer, 1000);
  animateProgress();
}

function setIdle() {
  state.scanRunning = false;
  document.getElementById("status-dot").className  = "status-dot done";
  document.getElementById("status-text").textContent = "Done";
  document.getElementById("btn-start").disabled = false;
  document.getElementById("btn-stop").classList.add("hidden");
  document.getElementById("progress-fill").style.width = "100%";
  clearInterval(state.timerInterval);
}

function animateProgress() {
  const steps = [
    [5000, 15], [10000, 30], [20000, 50],
    [40000, 70], [70000, 85], [120000, 93],
  ];
  steps.forEach(([delay, pct]) => {
    setTimeout(() => {
      if (state.scanRunning)
        document.getElementById("progress-fill").style.width = pct + "%";
    }, delay);
  });
}

function updateTimer() {
  const elapsed = Math.floor((Date.now() - state.startTime) / 1000);
  const m = String(Math.floor(elapsed / 60)).padStart(2, "0");
  const s = String(elapsed % 60).padStart(2, "0");
  document.getElementById("scan-timer").textContent = `${m}:${s}`;
}

// ── Terminal ───────────────────────────────────────────────────────────────
function appendLog(msg) {
  const term = document.getElementById("terminal");
  // Remove welcome screen on first log
  const welcome = term.querySelector(".term-welcome");
  if (welcome) welcome.remove();

  const div = document.createElement("div");
  div.className = "log-line " + classifyLog(msg);
  div.textContent = msg;
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
}

function log(msg, cls = "default") {
  const term = document.getElementById("terminal");
  const welcome = term.querySelector(".term-welcome");
  if (welcome) welcome.remove();
  const div = document.createElement("div");
  div.className = "log-line " + cls;
  div.textContent = msg;
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
}

function classifyLog(msg) {
  if (msg.startsWith("[+]") || msg.includes("Found") || msg.includes("complete")) return "success";
  if (msg.startsWith("[!]") || msg.includes("ERROR")) return "error";
  if (msg.startsWith("[*]")) return "section";
  if (msg.includes("WARNING") || msg.includes("[-]")) return "warning";
  if (msg.startsWith("  [")) return "info";
  return "default";
}

function clearTerminal(showWelcome = true) {
  const term = document.getElementById("terminal");
  term.innerHTML = "";
  if (showWelcome) {
    term.innerHTML = `<div class="term-welcome">
      <pre>  ____                      _   _               _    
 |  _ \\ ___  ___ ___  _ __ | | | | __ ___      | | __
 | |_) / _ \\/ __/ _ \\| '_ \\| |_| |/ _\` \\ \\ /\\ / |/ /
 |  _ <  __/ (_| (_) | | | |  _  | (_| |\\ V  V /|   < 
 |_| \\_\\___|\\___|\\___/|_| |_|_| |_|\\__,_| \\_/\\_/ |_|\\_\\</pre>
      <p>Configure your target and launch a scan →</p></div>`;
  }
}

// ── Results rendering ──────────────────────────────────────────────────────
function refreshResults() {
  fetch("/api/results")
    .then(r => r.json())
    .then(data => {
      state.results = data.results || {};
      renderResults();
      if (data.domain) document.getElementById("res-domain").textContent = data.domain;
    });
}

function renderResults() {
  renderSecrets();
  renderSubdomains();
  renderFuzz();
  renderPorts();
  renderEndpoints();
}

function updateSummaryCards(summary) {
  const c = document.getElementById("summary-cards");
  const cards = [
    { num: summary.subdomains_total, lbl: "Subdomains", cls: "" },
    { num: summary.subdomains_alive, lbl: "Alive", cls: "ok" },
    { num: summary.fuzz_hits,        lbl: "Fuzz Hits", cls: "" },
    { num: summary.secrets_critical, lbl: "Critical Secrets", cls: summary.secrets_critical ? "danger" : "" },
    { num: summary.secrets_high,     lbl: "High Secrets", cls: summary.secrets_high ? "warn" : "" },
    { num: summary.endpoints,        lbl: "Endpoints", cls: "" },
  ];
  c.innerHTML = cards.map(card =>
    `<div class="sum-card"><div class="num ${card.cls}">${card.num}</div><div class="lbl">${card.lbl}</div></div>`
  ).join("");
}

function renderSecrets() {
  const secrets = state.results.secrets || [];
  const filtered = state.sevFilter === "all"
    ? secrets
    : secrets.filter(s => s.severity === state.sevFilter);
  const tbody = document.getElementById("body-secrets");
  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty">${secrets.length ? "No results match filter" : "No secrets found"}</td></tr>`;
    return;
  }
  tbody.innerHTML = filtered.map(s => `
    <tr data-sev="${s.severity}">
      <td><span class="badge badge-${s.severity}">${s.severity}</span></td>
      <td>${esc(s.pattern)}</td>
      <td class="mono">${esc(s.match.substring(0, 120))}</td>
      <td class="mono">${esc(basename(s.file))}</td>
      <td>${s.line}</td>
    </tr>`).join("");
}

function renderSubdomains() {
  const subs = state.results.subdomains || [];
  const aliveOnly = document.getElementById("chk-alive-only")?.checked;
  const list = aliveOnly ? subs.filter(s => s.alive) : subs;
  const tbody = document.getElementById("body-subdomains");
  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">No subdomains found</td></tr>`;
    return;
  }
  tbody.innerHTML = list.map(s => `
    <tr>
      <td>${esc(s.host)}</td>
      <td><span class="status-${Math.floor((s.status||0)/100)}">${s.status || "-"}</span></td>
      <td class="mono">${esc(s.ip || "")}</td>
      <td><a href="${esc(s.url)}" target="_blank">${esc(s.url)}</a></td>
    </tr>`).join("");
}

function renderFuzz() {
  const hits = state.results.fuzz || [];
  const tbody = document.getElementById("body-fuzz");
  if (!hits.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">No paths found</td></tr>`;
    return;
  }
  tbody.innerHTML = hits.map(h => `
    <tr>
      <td><a href="${esc(h.url)}" target="_blank" class="mono">${esc(h.url)}</a></td>
      <td><span class="status-${Math.floor(h.status/100)}">${h.status}</span></td>
      <td>${h.size || "-"}</td>
      <td class="mono">${esc(h.content_type || "")}</td>
    </tr>`).join("");
}

function renderPorts() {
  const ports = state.results.ports || {};
  const tbody = document.getElementById("body-ports");
  const rows = [];
  for (const [host, openPorts] of Object.entries(ports)) {
    for (const p of openPorts) {
      rows.push(`<tr>
        <td class="mono">${esc(host)}</td>
        <td><strong>${p.port}</strong></td>
        <td>${esc(p.service)}</td>
        <td class="mono">${esc((p.banner || "").substring(0,80))}</td>
      </tr>`);
    }
  }
  tbody.innerHTML = rows.length
    ? rows.join("")
    : `<tr><td colspan="4" class="empty">No open ports found</td></tr>`;
}

function renderEndpoints() {
  const scraped = state.results.scraped || [];
  const endpointMap = {};
  scraped.forEach(item => {
    (item.endpoints || []).forEach(ep => {
      if (!endpointMap[ep]) endpointMap[ep] = item.url;
    });
  });
  const tbody = document.getElementById("body-endpoints");
  const entries = Object.entries(endpointMap).slice(0, 500);
  if (!entries.length) {
    tbody.innerHTML = `<tr><td colspan="2" class="empty">No endpoints discovered</td></tr>`;
    return;
  }
  tbody.innerHTML = entries.map(([ep, src]) => `
    <tr>
      <td class="mono">${esc(ep)}</td>
      <td class="mono" style="color:var(--muted);font-size:11px">${esc(src)}</td>
    </tr>`).join("");
}

// ── History ────────────────────────────────────────────────────────────────
function loadHistory() {
  fetch("/api/scans")
    .then(r => r.json())
    .then(scans => {
      const tbody = document.getElementById("body-history");
      if (!scans.length) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty">No scans found</td></tr>`;
        return;
      }
      tbody.innerHTML = scans.map(s => `
        <tr>
          <td><strong>${esc(s.domain || "-")}</strong></td>
          <td style="color:var(--muted)">${formatTs(s.timestamp)}</td>
          <td>${s.subdomains}</td>
          <td><span class="badge badge-${s.secrets > 0 ? "high" : "low"}">${s.secrets}</span></td>
          <td>
            <button class="btn-ghost" onclick="loadScan('${esc(s.file)}')">Load</button>
            <a href="/report/${s.file.replace('.json','.html')}" target="_blank" class="btn-ghost">Report</a>
          </td>
        </tr>`).join("");
    });
}

function loadScan(file) {
  fetch(`/api/scan/${file}`)
    .then(r => r.json())
    .then(data => {
      state.results = data.results || {};
      document.getElementById("res-domain").textContent = data.domain;
      updateSummaryCards({
        subdomains_total: (data.results.subdomains || []).length,
        subdomains_alive: (data.results.subdomains || []).filter(s => s.alive).length,
        fuzz_hits: (data.results.fuzz || []).length,
        secrets_total: (data.results.secrets || []).length,
        secrets_critical: (data.results.secrets || []).filter(s => s.severity === "critical").length,
        secrets_high: (data.results.secrets || []).filter(s => s.severity === "high").length,
        endpoints: (data.results.scraped || []).reduce((a, s) => a + (s.endpoints || []).length, 0),
      });
      switchView("results");
      toast(`Loaded scan: ${data.domain}`, "info");
    });
}

// ── Table filtering ────────────────────────────────────────────────────────
function filterTable(tableId, query) {
  const q = query.toLowerCase();
  document.querySelectorAll(`#${tableId} tbody tr`).forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? "" : "none";
  });
}

// ── Toast notifications ────────────────────────────────────────────────────
function toast(msg, type = "info") {
  const c = document.getElementById("toast-container");
  const t = document.createElement("div");
  t.className = `toast ${type}`;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ── Helpers ────────────────────────────────────────────────────────────────
function esc(str) {
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function basename(path) {
  return (path || "").split(/[/\\]/).pop();
}
function formatTs(ts) {
  if (!ts) return "-";
  const y = ts.slice(0,4), mo = ts.slice(4,6), d = ts.slice(6,8);
  const h = ts.slice(9,11), m = ts.slice(11,13);
  return `${d}/${mo}/${y} ${h}:${m}`;
}

// ── Enter key on domain input ──────────────────────────────────────────────
document.getElementById("inp-domain").addEventListener("keydown", e => {
  if (e.key === "Enter") startScan();
});

// ── Auto-fill output dir ───────────────────────────────────────────────────
document.getElementById("inp-domain").addEventListener("input", function() {
  const out = document.getElementById("inp-output");
  if (!out.dataset.touched) out.value = `reports/${this.value}`;
});
document.getElementById("inp-output").addEventListener("input", function() {
  this.dataset.touched = "1";
});

// ── Init ───────────────────────────────────────────────────────────────────
initSocket();
loadHistory();
