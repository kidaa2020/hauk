"""
ReconHawk Web UI - Flask + SocketIO (standalone, no templates/static folders needed)
"""
import os, sys, json, threading, datetime, glob, re
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_socketio import SocketIO, emit

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

scan_state = {"running": False, "domain": None, "results": {}, "log": [], "sid": None}

# ── Intercept print → WebSocket ───────────────────────────────────────────────
class WebPrint:
    def __init__(self, sid):
        self.sid = sid
    def write(self, text):
        if text.strip():
            clean = re.sub(r'\033\[[0-9;]*m', '', text.rstrip())
            scan_state["log"].append(clean)
            socketio.emit("log", {"msg": clean}, to=self.sid)
    def flush(self): pass

# ── CSS ───────────────────────────────────────────────────────────────────────
CSS = """
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;--text:#e6edf3;
--muted:#8b949e;--red:#ff4444;--orange:#f0883e;--yellow:#e3b341;--green:#3fb950;
--blue:#58a6ff;--purple:#bc8cff;--cyan:#39c5cf;--sidebar-w:220px}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;display:flex;height:100vh;overflow:hidden}
.sidebar{width:var(--sidebar-w);background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0}
.logo{display:flex;align-items:center;gap:10px;padding:20px 18px;border-bottom:1px solid var(--border)}
.logo-icon{font-size:22px}.logo-text{font-size:18px;font-weight:700;color:var(--blue)}
.nav-links{list-style:none;padding:12px 0;flex:1}
.nav-links li{padding:2px 8px}
.nav-link{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:6px;color:var(--muted);text-decoration:none;font-size:13.5px;transition:all .15s}
.nav-link:hover{background:var(--surface2);color:var(--text)}
.nav-link.active{background:rgba(88,166,255,.12);color:var(--blue);font-weight:600}
.sidebar-footer{display:flex;align-items:center;gap:8px;padding:14px 20px;border-top:1px solid var(--border);font-size:12px;color:var(--muted)}
.status-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.status-dot.idle{background:var(--muted)}.status-dot.running{background:var(--green);box-shadow:0 0 6px var(--green);animation:pulse 1.2s infinite}
.status-dot.done{background:var(--blue)}.status-dot.error{background:var(--red)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.main{flex:1;overflow-y:auto;padding:28px 32px;display:flex;flex-direction:column}
.view{display:none;flex-direction:column;gap:20px;height:100%}.view.active{display:flex}
.page-header{margin-bottom:4px}.page-header h1{font-size:22px;font-weight:700}
.page-header .sub{color:var(--muted);margin-top:4px}
.header-actions{display:flex;gap:8px;margin-top:8px}
.domain-badge{display:inline-block;background:rgba(88,166,255,.15);color:var(--blue);border:1px solid rgba(88,166,255,.3);border-radius:6px;padding:2px 10px;font-size:14px;font-weight:500;margin-left:10px}
.scan-layout{display:grid;grid-template-columns:380px 1fr;gap:20px;flex:1;min-height:0}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px;margin-bottom:14px}
.card:last-child{margin-bottom:0}
.card-title{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:14px}
.config-panel{overflow-y:auto;padding-right:4px}
.field{display:flex;flex-direction:column;gap:5px;margin-bottom:10px}
.field:last-child{margin-bottom:0}.field label{font-size:12px;color:var(--muted)}
.field input{background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:7px 10px;font-size:13px;font-family:inherit;transition:border-color .15s}
.field input:focus{outline:none;border-color:var(--blue)}
.field-row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.module-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.toggle-card{display:flex;flex-direction:column;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px;cursor:pointer;position:relative;transition:all .15s;user-select:none}
.toggle-card input{display:none}
.toggle-card .mod-icon{font-size:18px;margin-bottom:4px}
.toggle-card .mod-name{font-size:12px;font-weight:600}
.toggle-card .mod-desc{font-size:11px;color:var(--muted);margin-top:2px}
.toggle-card .toggle-check{position:absolute;top:8px;right:8px;width:16px;height:16px;border-radius:4px;border:1.5px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:10px;color:transparent;transition:all .15s}
.toggle-card.active{border-color:var(--blue);background:rgba(88,166,255,.07)}
.toggle-card.active .toggle-check{background:var(--blue);border-color:var(--blue);color:#fff}
.format-btns{display:flex;gap:6px}
.fmt-btn{flex:1;padding:7px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--muted);cursor:pointer;font-size:12px;font-weight:600;transition:all .15s}
.fmt-btn.active{background:var(--blue);border-color:var(--blue);color:#fff}
.action-row{display:flex;gap:10px;margin-top:6px}
.btn-primary{flex:1;background:linear-gradient(135deg,#1a6eff,var(--blue));color:#fff;border:none;border-radius:8px;padding:12px;font-size:14px;font-weight:700;cursor:pointer;transition:opacity .15s,transform .1s;letter-spacing:.3px}
.btn-primary:hover{opacity:.9}.btn-primary:active{transform:scale(.98)}.btn-primary:disabled{opacity:.5;cursor:not-allowed}
.btn-danger{background:var(--red);color:#fff;border:none;border-radius:8px;padding:12px 18px;font-size:14px;font-weight:700;cursor:pointer}
.btn-ghost{background:transparent;border:1px solid var(--border);color:var(--muted);border-radius:6px;padding:7px 14px;cursor:pointer;font-size:13px;transition:all .15s;text-decoration:none;display:inline-flex;align-items:center}
.btn-ghost:hover{border-color:var(--blue);color:var(--blue)}.hidden{display:none!important}
.terminal-panel{display:flex;flex-direction:column;background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden;min-height:0}
.terminal-header{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;border-bottom:1px solid var(--border);background:var(--surface2);flex-shrink:0}
.term-title{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.8px}
.term-controls{display:flex;align-items:center;gap:12px}
.scan-timer{font-size:12px;color:var(--green);font-family:monospace}
.terminal{flex:1;overflow-y:auto;padding:14px 16px;font-family:'Courier New',monospace;font-size:12.5px;line-height:1.6;background:#0a0e14}
.terminal::-webkit-scrollbar{width:6px}.terminal::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.term-welcome{color:var(--muted);text-align:center;padding:30px 0}
.term-welcome pre{color:var(--cyan);font-size:11px;line-height:1.4;margin-bottom:12px}
.log-line{padding:1px 0;white-space:pre-wrap;word-break:break-all}
.log-line.info{color:var(--cyan)}.log-line.success{color:var(--green)}.log-line.warning{color:var(--yellow)}
.log-line.error{color:var(--red)}.log-line.section{color:var(--blue);font-weight:bold}.log-line.default{color:#c9d1d9}
.progress-bar{height:3px;background:var(--border);position:relative;flex-shrink:0}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--blue),var(--cyan));width:0%;transition:width .5s ease}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:8px}
.sum-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center}
.sum-card .num{font-size:32px;font-weight:800;color:var(--blue);line-height:1}
.sum-card .num.danger{color:var(--red)}.sum-card .num.warn{color:var(--orange)}.sum-card .num.ok{color:var(--green)}
.sum-card .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-top:4px}
.tabs-container{flex:1;display:flex;flex-direction:column;min-height:0}
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--border);flex-shrink:0}
.tab{padding:9px 16px;background:transparent;border:none;border-bottom:2px solid transparent;color:var(--muted);cursor:pointer;font-size:13px;transition:all .15s}
.tab:hover{color:var(--text)}.tab.active{color:var(--blue);border-bottom-color:var(--blue)}
.tab-content{display:none;flex-direction:column;flex:1;min-height:0;padding-top:14px}.tab-content.active{display:flex}
.table-controls{display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap}
.search-box{flex:1;min-width:200px;max-width:340px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:7px 12px;font-size:13px}
.search-box:focus{outline:none;border-color:var(--blue)}
.toggle-filter{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:13px;cursor:pointer}
.filter-chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{padding:4px 12px;border-radius:20px;border:1px solid var(--border);background:transparent;color:var(--muted);cursor:pointer;font-size:12px;font-weight:600;transition:all .15s}
.chip.active,.chip:hover{background:var(--surface2);color:var(--text)}
.chip.critical.active{background:rgba(255,68,68,.15);border-color:var(--red);color:var(--red)}
.chip.high.active{background:rgba(240,136,62,.15);border-color:var(--orange);color:var(--orange)}
.chip.medium.active{background:rgba(227,179,65,.15);border-color:var(--yellow);color:var(--yellow)}
.chip.low.active{background:rgba(63,185,80,.15);border-color:var(--green);color:var(--green)}
.table-wrap{flex:1;overflow:auto;border:1px solid var(--border);border-radius:8px}
.table-wrap::-webkit-scrollbar{width:6px;height:6px}.table-wrap::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
table{width:100%;border-collapse:collapse}thead{position:sticky;top:0;z-index:1}
th{background:var(--surface2);color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.8px;padding:10px 14px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:10px 14px;border-bottom:1px solid #1c2128;vertical-align:top;max-width:400px}
tr:hover td{background:rgba(88,166,255,.04)}.empty{color:var(--muted);font-style:italic;text-align:center;padding:30px}
.mono{font-family:monospace;font-size:12px;word-break:break-all}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;white-space:nowrap}
.badge-critical{background:rgba(255,68,68,.15);color:var(--red);border:1px solid rgba(255,68,68,.4)}
.badge-high{background:rgba(240,136,62,.15);color:var(--orange);border:1px solid rgba(240,136,62,.4)}
.badge-medium{background:rgba(227,179,65,.15);color:var(--yellow);border:1px solid rgba(227,179,65,.4)}
.badge-low{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.4)}
.status-2{color:var(--green)}.status-3{color:var(--orange)}.status-4{color:var(--blue)}.status-5{color:var(--red)}
#toast-container{position:fixed;bottom:24px;right:24px;display:flex;flex-direction:column;gap:8px;z-index:999}
.toast{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px 18px;font-size:13px;animation:slideIn .2s ease;max-width:300px}
.toast.success{border-left:3px solid var(--green)}.toast.error{border-left:3px solid var(--red)}.toast.info{border-left:3px solid var(--blue)}
@keyframes slideIn{from{transform:translateX(20px);opacity:0}to{transform:translateX(0);opacity:1}}
@media(max-width:900px){.scan-layout{grid-template-columns:1fr}.sidebar{display:none}}
"""

# ── JS ────────────────────────────────────────────────────────────────────────
JS = r"""
const state={socket:null,results:{},scanRunning:false,startTime:null,timerInterval:null,activeView:"scan",sevFilter:"all"};
function initSocket(){
  state.socket=io();
  state.socket.on("connect",()=>log("[+] Connected","success"));
  state.socket.on("disconnect",()=>log("[!] Disconnected","warning"));
  state.socket.on("log_history",({lines})=>lines.forEach(l=>appendLog(l)));
  state.socket.on("log",({msg})=>appendLog(msg));
  state.socket.on("status",({running,domain})=>{if(running)setRunning(domain);});
  state.socket.on("scan_started",({domain})=>{toast("Scan started: "+domain,"info");setRunning(domain);clearTerminal(false);switchView("scan");});
  state.socket.on("partial_result",({key,data})=>{state.results[key]=data;if(state.activeView==="results")renderResults();});
  state.socket.on("scan_done",({domain,summary,report_dir})=>{
    setIdle();toast("Scan complete: "+domain,"success");updateSummaryCards(summary);renderResults();
    const link=document.getElementById("link-html-report");link.classList.remove("hidden");
    fetch("/api/scans").then(r=>r.json()).then(scans=>{const m=scans.find(s=>s.domain===domain);if(m)link.href="/report/"+m.file.replace(".json",".html");});
    switchView("results");
  });
  state.socket.on("scan_error",({msg})=>{setIdle();toast("Error: "+msg,"error");log("[ERROR] "+msg,"error");});
  state.socket.on("error",({msg})=>toast(msg,"error"));
}
function switchView(view){
  state.activeView=view;
  document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));
  document.getElementById("view-"+view).classList.add("active");
  document.querySelectorAll(".nav-link").forEach(l=>l.classList.toggle("active",l.dataset.view===view));
  if(view==="results")renderResults();
  if(view==="history")loadHistory();
}
document.querySelectorAll(".nav-link").forEach(l=>l.addEventListener("click",e=>{e.preventDefault();switchView(l.dataset.view);}));
document.querySelectorAll(".tab").forEach(btn=>btn.addEventListener("click",()=>{
  document.querySelectorAll(".tab").forEach(t=>t.classList.remove("active"));
  document.querySelectorAll(".tab-content").forEach(t=>t.classList.remove("active"));
  btn.classList.add("active");document.getElementById("tab-"+btn.dataset.tab).classList.add("active");
}));
document.querySelectorAll(".toggle-card").forEach(card=>card.addEventListener("click",()=>{
  const chk=card.querySelector("input[type=checkbox]");chk.checked=!chk.checked;card.classList.toggle("active",chk.checked);
}));
document.querySelectorAll(".fmt-btn").forEach(btn=>btn.addEventListener("click",()=>{
  document.querySelectorAll(".fmt-btn").forEach(b=>b.classList.remove("active"));btn.classList.add("active");
}));
document.querySelectorAll("#sev-filters .chip").forEach(chip=>chip.addEventListener("click",()=>{
  document.querySelectorAll("#sev-filters .chip").forEach(c=>c.classList.remove("active"));
  chip.classList.add("active");state.sevFilter=chip.dataset.sev;renderSecrets();
}));
function startScan(){
  const domain=document.getElementById("inp-domain").value.trim();
  if(!domain){toast("Enter a domain first","error");return;}
  const mc=mod=>document.querySelector('.toggle-card[data-mod="'+mod+'"] input').checked;
  const fmt=document.querySelector(".fmt-btn.active");
  state.socket.emit("start_scan",{
    domain,output:document.getElementById("inp-output").value||"reports/"+domain,
    threads:document.getElementById("inp-threads").value,timeout:document.getElementById("inp-timeout").value,
    depth:document.getElementById("inp-depth").value,wordlist:document.getElementById("inp-wordlist").value,
    ports:document.getElementById("inp-ports").value,passive:mc("passive"),
    format:fmt?fmt.dataset.fmt:"both",skip_subdomains:!mc("subdomains"),skip_ports:!mc("ports"),
    skip_fuzz:!mc("fuzz"),skip_scrape:!mc("scrape"),skip_secrets:!mc("secrets"),
  });
}
function stopScan(){state.socket.emit("stop_scan");toast("Stop requested...","info");}
function setRunning(domain){
  state.scanRunning=true;state.startTime=Date.now();
  document.getElementById("status-dot").className="status-dot running";
  document.getElementById("status-text").textContent="Scanning";
  document.getElementById("btn-start").disabled=true;
  document.getElementById("btn-stop").classList.remove("hidden");
  document.getElementById("progress-bar").classList.remove("hidden");
  document.getElementById("progress-fill").style.width="0%";
  document.getElementById("res-domain").textContent=domain;
  state.timerInterval=setInterval(updateTimer,1000);animateProgress();
}
function setIdle(){
  state.scanRunning=false;
  document.getElementById("status-dot").className="status-dot done";
  document.getElementById("status-text").textContent="Done";
  document.getElementById("btn-start").disabled=false;
  document.getElementById("btn-stop").classList.add("hidden");
  document.getElementById("progress-fill").style.width="100%";
  clearInterval(state.timerInterval);
}
function animateProgress(){
  [[5000,15],[10000,30],[20000,50],[40000,70],[70000,85],[120000,93]].forEach(([d,p])=>{
    setTimeout(()=>{if(state.scanRunning)document.getElementById("progress-fill").style.width=p+"%";},d);
  });
}
function updateTimer(){
  const e=Math.floor((Date.now()-state.startTime)/1000);
  const m=String(Math.floor(e/60)).padStart(2,"0"),s=String(e%60).padStart(2,"0");
  document.getElementById("scan-timer").textContent=m+":"+s;
}
function appendLog(msg){
  const term=document.getElementById("terminal");
  const w=term.querySelector(".term-welcome");if(w)w.remove();
  const div=document.createElement("div");div.className="log-line "+classifyLog(msg);div.textContent=msg;
  term.appendChild(div);term.scrollTop=term.scrollHeight;
}
function log(msg,cls="default"){appendLog(msg);}
function classifyLog(msg){
  if(msg.startsWith("[+]")||msg.includes("Found")||msg.includes("complete"))return"success";
  if(msg.startsWith("[!]")||msg.includes("ERROR"))return"error";
  if(msg.startsWith("[*]"))return"section";
  if(msg.includes("WARNING")||msg.includes("[-]"))return"warning";
  if(msg.startsWith("  ["))return"info";
  return"default";
}
function clearTerminal(showWelcome=true){
  const term=document.getElementById("terminal");term.innerHTML="";
  if(showWelcome)term.innerHTML='<div class="term-welcome"><pre>  ReconHawk Ready</pre><p>Configure your target and launch a scan</p></div>';
}
function refreshResults(){fetch("/api/results").then(r=>r.json()).then(data=>{state.results=data.results||{};renderResults();if(data.domain)document.getElementById("res-domain").textContent=data.domain;});}
function renderResults(){renderSecrets();renderSubdomains();renderFuzz();renderPorts();renderEndpoints();}
function updateSummaryCards(s){
  document.getElementById("summary-cards").innerHTML=[
    {num:s.subdomains_total,lbl:"Subdomains",cls:""},
    {num:s.subdomains_alive,lbl:"Alive",cls:"ok"},
    {num:s.fuzz_hits,lbl:"Fuzz Hits",cls:""},
    {num:s.secrets_critical,lbl:"Critical",cls:s.secrets_critical?"danger":""},
    {num:s.secrets_high,lbl:"High Secrets",cls:s.secrets_high?"warn":""},
    {num:s.endpoints,lbl:"Endpoints",cls:""},
  ].map(c=>'<div class="sum-card"><div class="num '+c.cls+'">'+c.num+'</div><div class="lbl">'+c.lbl+'</div></div>').join("");
}
function renderSecrets(){
  const all=state.results.secrets||[];
  const list=state.sevFilter==="all"?all:all.filter(s=>s.severity===state.sevFilter);
  const tb=document.getElementById("body-secrets");
  if(!list.length){tb.innerHTML='<tr><td colspan="5" class="empty">'+(all.length?"No match":"No secrets found")+'</td></tr>';return;}
  tb.innerHTML=list.map(s=>'<tr><td><span class="badge badge-'+s.severity+'">'+s.severity+'</span></td><td>'+esc(s.pattern)+'</td><td class="mono">'+esc(s.match.substring(0,120))+'</td><td class="mono">'+esc(bn(s.file))+'</td><td>'+s.line+'</td></tr>').join("");
}
// Type badge colors
const TYPE_COLORS={
  "Admin":"#ff4444","API":"#58a6ff","Auth":"#f0883e","Dev/Stage":"#e3b341",
  "Git/CI":"#bc8cff","Monitoring":"#39c5cf","Mail":"#3fb950","Database":"#ff4444",
  "CDN/Media":"#8b949e","VPN/Remote":"#f0883e","Shop":"#3fb950","Mobile":"#58a6ff",
  "Docs":"#8b949e","Web":"#3fb950","Unknown":"#8b949e"
};
function typeBadge(t){const c=TYPE_COLORS[t]||"#8b949e";return'<span style="display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;background:'+c+'22;color:'+c+';border:1px solid '+c+'55">'+esc(t||"Web")+'</span>';}

function buildTypeFilters(){
  const all=state.results.subdomains||[];
  const types=[...new Set(all.map(s=>s.type||"Web"))].sort();
  const el=document.getElementById("type-filters");
  if(!el)return;
  el.innerHTML='<button class="chip active" data-type="all" onclick="filterByType(this)">All ('+all.length+')</button>'
    +types.map(t=>{const n=all.filter(s=>(s.type||"Web")===t).length;return'<button class="chip" data-type="'+esc(t)+'" onclick="filterByType(this)">'+esc(t)+' ('+n+')</button>';}).join("");
}
function filterByType(btn){
  document.querySelectorAll("#type-filters .chip").forEach(c=>c.classList.remove("active"));
  btn.classList.add("active");
  state.typeFilter=btn.dataset.type;
  renderSubdomains();
}
function renderSubdomains(){
  const all=state.results.subdomains||[];
  buildTypeFilters();
  const ao=document.getElementById("chk-alive-only")?.checked;
  const tf=state.typeFilter||"all";
  let list=ao?all.filter(s=>s.alive):all;
  if(tf!=="all")list=list.filter(s=>(s.type||"Web")===tf);
  const tb=document.getElementById("body-subdomains");
  if(!list.length){tb.innerHTML='<tr><td colspan="6" class="empty">No subdomains found</td></tr>';return;}
  tb.innerHTML=list.map(s=>'<tr>'
    +'<td>'+typeBadge(s.type||"Web")+'</td>'
    +'<td><a href="'+esc(s.url)+'" target="_blank" class="mono">'+esc(s.host)+'</a></td>'
    +'<td><span class="status-'+Math.floor((s.status||0)/100)+'">'+(s.status||"-")+'</span></td>'
    +'<td class="mono" style="font-size:11px;color:var(--muted)">'+esc(s.ip||"")+'</td>'
    +'<td style="font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(s.title||"")+'</td>'
    +'<td class="mono" style="font-size:11px;color:var(--muted)">'+esc(s.webserver||"")+'</td>'
    +'</tr>').join("");
}
function renderFuzz(){
  const list=state.results.fuzz||[];
  const tb=document.getElementById("body-fuzz");
  if(!list.length){tb.innerHTML='<tr><td colspan="5" class="empty">No paths found — check if the target uses HTTP (not HTTPS)</td></tr>';return;}
  tb.innerHTML=list.map(h=>'<tr>'
    +'<td><a href="'+esc(h.url)+'" target="_blank" class="mono" style="font-size:12px">'+esc(h.url)+'</a></td>'
    +'<td><span class="status-'+Math.floor(h.status/100)+'">'+h.status+'</span></td>'
    +'<td style="color:var(--muted)">'+fmtSize(h.size)+'</td>'
    +'<td class="mono" style="font-size:11px;color:var(--muted)">'+esc((h.content_type||"").split(";")[0])+'</td>'
    +'<td class="mono" style="font-size:11px;color:var(--muted)">'+esc(h.server||"")+'</td>'
    +'</tr>').join("");
}
function fmtSize(n){if(!n)return"-";if(n>1048576)return(n/1048576).toFixed(1)+"MB";if(n>1024)return(n/1024).toFixed(1)+"KB";return n+"B";}
function renderPorts(){
  const ports=state.results.ports||{};const tb=document.getElementById("body-ports");const rows=[];
  for(const[host,ps]of Object.entries(ports))for(const p of ps)rows.push('<tr><td class="mono">'+esc(host)+'</td><td><strong>'+p.port+'</strong></td><td>'+esc(p.service)+'</td><td class="mono">'+esc((p.banner||"").substring(0,80))+'</td></tr>');
  tb.innerHTML=rows.length?rows.join(""):'<tr><td colspan="4" class="empty">No open ports found</td></tr>';
}
function renderEndpoints(){
  const map={};(state.results.scraped||[]).forEach(item=>(item.endpoints||[]).forEach(ep=>{if(!map[ep])map[ep]=item.url;}));
  const tb=document.getElementById("body-endpoints");const entries=Object.entries(map).slice(0,500);
  if(!entries.length){tb.innerHTML='<tr><td colspan="2" class="empty">No endpoints discovered</td></tr>';return;}
  tb.innerHTML=entries.map(([ep,src])=>'<tr><td class="mono">'+esc(ep)+'</td><td class="mono" style="color:var(--muted);font-size:11px">'+esc(src)+'</td></tr>').join("");
}
function loadHistory(){
  fetch("/api/scans").then(r=>r.json()).then(scans=>{
    const tb=document.getElementById("body-history");
    if(!scans.length){tb.innerHTML='<tr><td colspan="5" class="empty">No scans found</td></tr>';return;}
    tb.innerHTML=scans.map(s=>'<tr><td><strong>'+esc(s.domain||"-")+'</strong></td><td style="color:var(--muted)">'+fmtTs(s.timestamp)+'</td><td>'+s.subdomains+'</td><td><span class="badge badge-'+(s.secrets>0?"high":"low")+'">'+s.secrets+'</span></td><td><button class="btn-ghost" onclick="loadScan(\''+esc(s.file)+'\')">Load</button> <a href="/report/'+s.file.replace(".json",".html")+'" target="_blank" class="btn-ghost">Report</a></td></tr>').join("");
  });
}
function loadScan(file){
  fetch("/api/scan/"+file).then(r=>r.json()).then(data=>{
    state.results=data.results||{};document.getElementById("res-domain").textContent=data.domain;
    const r=data.results||{};
    updateSummaryCards({subdomains_total:(r.subdomains||[]).length,subdomains_alive:(r.subdomains||[]).filter(s=>s.alive).length,fuzz_hits:(r.fuzz||[]).length,secrets_total:(r.secrets||[]).length,secrets_critical:(r.secrets||[]).filter(s=>s.severity==="critical").length,secrets_high:(r.secrets||[]).filter(s=>s.severity==="high").length,endpoints:(r.scraped||[]).reduce((a,s)=>a+(s.endpoints||[]).length,0)});
    switchView("results");toast("Loaded: "+data.domain,"info");
  });
}
function filterTable(id,q){document.querySelectorAll("#"+id+" tbody tr").forEach(row=>row.style.display=row.textContent.toLowerCase().includes(q.toLowerCase())?"":"none");}
function toast(msg,type="info"){const c=document.getElementById("toast-container");const t=document.createElement("div");t.className="toast "+type;t.textContent=msg;c.appendChild(t);setTimeout(()=>t.remove(),4000);}
function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
function bn(p){return(p||"").split(/[/\\]/).pop();}
function fmtTs(ts){if(!ts)return"-";return ts.slice(6,8)+"/"+ts.slice(4,6)+"/"+ts.slice(0,4)+" "+ts.slice(9,11)+":"+ts.slice(11,13);}
document.getElementById("inp-domain").addEventListener("keydown",e=>{if(e.key==="Enter")startScan();});
document.getElementById("inp-domain").addEventListener("input",function(){const o=document.getElementById("inp-output");if(!o.dataset.touched)o.value="reports/"+this.value;});
document.getElementById("inp-output").addEventListener("input",function(){this.dataset.touched="1";});
initSocket();loadHistory();
"""

# ── HTML ──────────────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconHawk</title>
<script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
<style>{CSS}</style></head><body>
<nav class="sidebar">
  <div class="logo"><span class="logo-icon">🦅</span><span class="logo-text">ReconHawk</span></div>
  <ul class="nav-links">
    <li><a href="#" class="nav-link active" data-view="scan"><span class="icon">⚡</span> New Scan</a></li>
    <li><a href="#" class="nav-link" data-view="results"><span class="icon">📊</span> Results</a></li>
    <li><a href="#" class="nav-link" data-view="history"><span class="icon">📁</span> History</a></li>
  </ul>
  <div class="sidebar-footer"><div id="status-dot" class="status-dot idle"></div><span id="status-text">Idle</span></div>
</nav>
<main class="main">
  <div id="view-scan" class="view active">
    <div class="page-header"><h1>New Scan</h1><p class="sub">Configure and launch a recon session</p></div>
    <div class="scan-layout">
      <div class="config-panel">
        <div class="card"><div class="card-title">🎯 Target</div>
          <div class="field"><label>Domain</label><input id="inp-domain" type="text" placeholder="example.com" autocomplete="off" spellcheck="false"></div>
          <div class="field-row">
            <div class="field"><label>Output Dir</label><input id="inp-output" type="text" placeholder="reports/example.com"></div>
            <div class="field"><label>Threads</label><input id="inp-threads" type="number" value="50" min="1" max="500"></div>
          </div>
          <div class="field-row">
            <div class="field"><label>Timeout (s)</label><input id="inp-timeout" type="number" value="10" min="1" max="60"></div>
            <div class="field"><label>Crawl Depth</label><input id="inp-depth" type="number" value="2" min="1" max="5"></div>
          </div>
          <div class="field"><label>Custom Wordlist</label><input id="inp-wordlist" type="text" placeholder="/usr/share/wordlists/dirb/common.txt"></div>
          <div class="field"><label>Ports</label><input id="inp-ports" type="text" value="21,22,25,53,80,443,445,3306,3389,5432,6379,8080,8443,8888,9200,27017"></div>
        </div>
        <div class="card"><div class="card-title">⚙️ Modules</div>
          <div class="module-grid">
            <label class="toggle-card active" data-mod="subdomains"><input type="checkbox" checked><span class="mod-icon">🌐</span><span class="mod-name">Subdomains</span><span class="mod-desc">OSINT + DNS brute-force</span><div class="toggle-check">✓</div></label>
            <label class="toggle-card active" data-mod="ports"><input type="checkbox" checked><span class="mod-icon">🔌</span><span class="mod-name">Port Scan</span><span class="mod-desc">Banner grabbing</span><div class="toggle-check">✓</div></label>
            <label class="toggle-card active" data-mod="fuzz"><input type="checkbox" checked><span class="mod-icon">📂</span><span class="mod-name">Dir Fuzzing</span><span class="mod-desc">150+ sensitive paths</span><div class="toggle-check">✓</div></label>
            <label class="toggle-card active" data-mod="scrape"><input type="checkbox" checked><span class="mod-icon">🕷️</span><span class="mod-name">Scraper</span><span class="mod-desc">HTML + JS download</span><div class="toggle-check">✓</div></label>
            <label class="toggle-card active" data-mod="secrets"><input type="checkbox" checked><span class="mod-icon">🔐</span><span class="mod-name">Secret Hunt</span><span class="mod-desc">35+ leak patterns</span><div class="toggle-check">✓</div></label>
            <label class="toggle-card" data-mod="passive"><input type="checkbox"><span class="mod-icon">👻</span><span class="mod-name">Passive Only</span><span class="mod-desc">No active probing</span><div class="toggle-check">✓</div></label>
          </div>
        </div>
        <div class="card"><div class="card-title">📄 Report Format</div>
          <div class="format-btns"><button class="fmt-btn active" data-fmt="both">Both</button><button class="fmt-btn" data-fmt="html">HTML</button><button class="fmt-btn" data-fmt="json">JSON</button></div>
        </div>
        <div class="action-row">
          <button id="btn-start" class="btn-primary" onclick="startScan()">▶ Launch Scan</button>
          <button id="btn-stop" class="btn-danger hidden" onclick="stopScan()">⏹ Stop</button>
        </div>
      </div>
      <div class="terminal-panel">
        <div class="terminal-header">
          <span class="term-title">Terminal Output</span>
          <div class="term-controls"><span id="scan-timer" class="scan-timer"></span><button class="btn-ghost" onclick="clearTerminal()">Clear</button></div>
        </div>
        <div id="terminal" class="terminal">
          <div class="term-welcome"><pre>  ____                      _   _               _    
 |  _ \\ ___  ___ ___  _ __ | | | | __ ___      | | __
 | |_) / _ \\/ __/ _ \\| '_ \\| |_| |/ _` \\ \\ /\\ / |/ /
 |  _ &lt;  __/ (_| (_) | | | |  _  | (_| |\\ V  V /|   &lt;
 |_| \\_\\___|\\___|\\___/|_| |_|_| |_|\\__,_| \\_/\\_/ |_|\\_\\</pre>
          <p>Configure your target and launch a scan →</p></div>
        </div>
        <div id="progress-bar" class="progress-bar hidden"><div id="progress-fill" class="progress-fill"></div></div>
      </div>
    </div>
  </div>

  <div id="view-results" class="view">
    <div class="page-header"><h1>Results <span id="res-domain" class="domain-badge"></span></h1>
      <div class="header-actions"><button class="btn-ghost" onclick="refreshResults()">↻ Refresh</button><a id="link-html-report" href="#" target="_blank" class="btn-ghost hidden">📄 Open Report</a></div>
    </div>
    <div id="summary-cards" class="summary-grid"></div>
    <div class="tabs-container">
      <div class="tabs">
        <button class="tab active" data-tab="secrets">🔐 Secrets</button>
        <button class="tab" data-tab="subdomains">🌐 Subdomains</button>
        <button class="tab" data-tab="fuzz">📂 Fuzzing</button>
        <button class="tab" data-tab="ports">🔌 Ports</button>
        <button class="tab" data-tab="endpoints">🔗 Endpoints</button>
      </div>
      <div id="tab-secrets" class="tab-content active">
        <div class="table-controls">
          <input class="search-box" placeholder="Filter secrets..." oninput="filterTable('tbl-secrets',this.value)">
          <div class="filter-chips" id="sev-filters"><button class="chip active" data-sev="all">All</button><button class="chip critical" data-sev="critical">Critical</button><button class="chip high" data-sev="high">High</button><button class="chip medium" data-sev="medium">Medium</button><button class="chip low" data-sev="low">Low</button></div>
        </div>
        <div class="table-wrap"><table id="tbl-secrets"><thead><tr><th>Severity</th><th>Type</th><th>Match</th><th>File</th><th>Line</th></tr></thead><tbody id="body-secrets"><tr><td colspan="5" class="empty">No scan data yet</td></tr></tbody></table></div>
      </div>
      <div id="tab-subdomains" class="tab-content">
        <div class="table-controls">
          <input class="search-box" placeholder="Filter subdomains..." oninput="filterTable('tbl-subdomains',this.value)">
          <label class="toggle-filter"><input type="checkbox" id="chk-alive-only" onchange="renderSubdomains()"> Alive only</label>
        </div>
        <div class="filter-chips" id="type-filters" style="margin-bottom:10px"></div>
        <div class="table-wrap"><table id="tbl-subdomains"><thead><tr><th>Type</th><th>Host</th><th>Status</th><th>IP</th><th>Title</th><th>Server</th></tr></thead><tbody id="body-subdomains"><tr><td colspan="6" class="empty">No scan data yet</td></tr></tbody></table></div>
      </div>
      <div id="tab-fuzz" class="tab-content">
        <div class="table-controls"><input class="search-box" placeholder="Filter paths..." oninput="filterTable('tbl-fuzz',this.value)"></div>
        <div class="table-wrap"><table id="tbl-fuzz"><thead><tr><th>URL</th><th>Status</th><th>Size</th><th>Content-Type</th><th>Server</th></tr></thead><tbody id="body-fuzz"><tr><td colspan="5" class="empty">No scan data yet</td></tr></tbody></table></div>
      </div>
      <div id="tab-ports" class="tab-content">
        <div class="table-wrap"><table id="tbl-ports"><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Banner</th></tr></thead><tbody id="body-ports"><tr><td colspan="4" class="empty">No scan data yet</td></tr></tbody></table></div>
      </div>
      <div id="tab-endpoints" class="tab-content">
        <div class="table-controls"><input class="search-box" placeholder="Filter endpoints..." oninput="filterTable('tbl-endpoints',this.value)"></div>
        <div class="table-wrap"><table id="tbl-endpoints"><thead><tr><th>Endpoint</th><th>Source</th></tr></thead><tbody id="body-endpoints"><tr><td colspan="2" class="empty">No scan data yet</td></tr></tbody></table></div>
      </div>
    </div>
  </div>

  <div id="view-history" class="view">
    <div class="page-header"><h1>Scan History</h1><button class="btn-ghost" onclick="loadHistory()">↻ Refresh</button></div>
    <div class="table-wrap"><table id="tbl-history"><thead><tr><th>Domain</th><th>Date</th><th>Subdomains</th><th>Secrets</th><th>Actions</th></tr></thead><tbody id="body-history"><tr><td colspan="5" class="empty">Loading...</td></tr></tbody></table></div>
  </div>
</main>
<div id="toast-container"></div>
<script>{JS}</script>
</body></html>"""

RENDERED_HTML = HTML.replace("{CSS}", CSS).replace("{JS}", JS)

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return Response(RENDERED_HTML, mimetype="text/html")

@app.route("/api/scans")
def list_scans():
    reports = []
    for f in sorted(glob.glob(os.path.join(BASE_DIR, "*/report_*.json")), reverse=True)[:30]:
        try:
            with open(f) as fh:
                data = json.load(fh)
            reports.append({"file": os.path.relpath(f, BASE_DIR), "domain": data.get("domain"),
                             "timestamp": data.get("timestamp"),
                             "subdomains": len(data.get("results", {}).get("subdomains", [])),
                             "secrets": len(data.get("results", {}).get("secrets", []))})
        except Exception:
            pass
    return jsonify(reports)

@app.route("/api/scan/<path:filename>")
def get_scan(filename):
    try:
        with open(os.path.join(BASE_DIR, filename)) as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({"error": str(e)}), 404

@app.route("/api/results")
def current_results():
    return jsonify({"running": scan_state["running"], "domain": scan_state["domain"],
                    "results": scan_state["results"], "log": scan_state["log"][-200:]})

@app.route("/report/<path:filename>")
def serve_report(filename):
    return send_from_directory(BASE_DIR, filename)

# ── WebSocket events ───────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    emit("status", {"running": scan_state["running"], "domain": scan_state["domain"]})
    if scan_state["log"]:
        emit("log_history", {"lines": scan_state["log"][-300:]})

@socketio.on("start_scan")
def on_start_scan(data):
    if scan_state["running"]:
        emit("error", {"msg": "A scan is already running"}); return
    sid = request.sid
    domain = data.get("domain", "").strip()
    if not domain:
        emit("error", {"msg": "Domain required"}); return
    opts = {
        "output": data.get("output", f"reports/{domain}"),
        "threads": int(data.get("threads", 50)), "timeout": int(data.get("timeout", 10)),
        "wordlist": data.get("wordlist") or None, "depth": int(data.get("depth", 2)),
        "ports": data.get("ports", "21,22,80,443,3306,3389,8080"),
        "passive": bool(data.get("passive", False)), "format": data.get("format", "both"),
        "skip_subdomains": bool(data.get("skip_subdomains", False)),
        "skip_fuzz": bool(data.get("skip_fuzz", False)),
        "skip_scrape": bool(data.get("skip_scrape", False)),
        "skip_secrets": bool(data.get("skip_secrets", False)),
        "skip_ports": bool(data.get("skip_ports", False)),
    }
    scan_state.update({"running": True, "domain": domain, "results": {}, "log": [],
                        "start_time": datetime.datetime.now().isoformat(), "sid": sid})
    socketio.emit("scan_started", {"domain": domain})
    threading.Thread(target=run_scan, args=(domain, opts, sid), daemon=True).start()

@socketio.on("stop_scan")
def on_stop_scan():
    scan_state["running"] = False
    emit("log", {"msg": "[!] Scan stop requested"})

# ── Background scan runner ────────────────────────────────────────────────────
def run_scan(domain, opts, sid):
    old_stdout = sys.stdout
    sys.stdout = WebPrint(sid)
    try:
        sys.path.insert(0, BASE_DIR)
        from modules.subdomains import SubdomainScanner
        from modules.fuzzer import DirectoryFuzzer
        from modules.scraper import SourceScraper
        from modules.secrets import SecretHunter
        from modules.portscan import PortScanner
        from modules.reporter import Reporter

        results = {}
        output = os.path.join(BASE_DIR, opts["output"])
        os.makedirs(output, exist_ok=True)
        reporter = Reporter(domain, output)

        if not opts["skip_subdomains"]:
            print(f"\n[*] Subdomain enumeration → {domain}")
            subdomains = SubdomainScanner(domain, threads=opts["threads"], timeout=opts["timeout"], passive=opts["passive"]).run()
            results["subdomains"] = subdomains
            socketio.emit("partial_result", {"key": "subdomains", "data": subdomains}, to=sid)
            print(f"[+] {len(subdomains)} subdomains found")

        if not opts["skip_ports"] and not opts["passive"]:
            targets = [domain] + [s["host"] for s in results.get("subdomains", []) if s.get("alive")]
            print(f"\n[*] Port scanning {len(targets[:20])} hosts")
            results["ports"] = PortScanner(targets[:20], opts["ports"], threads=opts["threads"], timeout=opts["timeout"]).run()
            socketio.emit("partial_result", {"key": "ports", "data": results["ports"]}, to=sid)

        if not opts["skip_fuzz"]:
            fuzz_t = list(dict.fromkeys([f"https://{domain}", f"http://{domain}"] + [s["url"] for s in results.get("subdomains", []) if s.get("alive")]))[:10]
            print(f"\n[*] Fuzzing {len(fuzz_t)} targets")
            results["fuzz"] = DirectoryFuzzer(fuzz_t, wordlist=opts["wordlist"], threads=opts["threads"], timeout=opts["timeout"]).run()
            socketio.emit("partial_result", {"key": "fuzz", "data": results["fuzz"]}, to=sid)

        if not opts["skip_scrape"]:
            scrape_t = list(dict.fromkeys([f"https://{domain}"] + [s["url"] for s in results.get("subdomains", []) if s.get("alive")]))[:15]
            print(f"\n[*] Scraping {len(scrape_t)} targets")
            results["scraped"] = SourceScraper(scrape_t, depth=opts["depth"], threads=opts["threads"], timeout=opts["timeout"], output_dir=output).run()
            socketio.emit("partial_result", {"key": "scraped", "data": results["scraped"]}, to=sid)

        if not opts["skip_secrets"]:
            print(f"\n[*] Hunting secrets...")
            results["secrets"] = SecretHunter(output).run()
            socketio.emit("partial_result", {"key": "secrets", "data": results["secrets"]}, to=sid)

        print(f"\n[*] Generating report...")
        reporter.generate(results, fmt=opts["format"])
        scan_state["results"] = results
        subs = results.get("subdomains", []); secs = results.get("secrets", [])
        socketio.emit("scan_done", {"domain": domain, "report_dir": opts["output"], "summary": {
            "subdomains_total": len(subs), "subdomains_alive": sum(1 for s in subs if s.get("alive")),
            "fuzz_hits": len(results.get("fuzz", [])), "secrets_total": len(secs),
            "secrets_critical": sum(1 for s in secs if s.get("severity") == "critical"),
            "secrets_high": sum(1 for s in secs if s.get("severity") == "high"),
            "endpoints": sum(len(s.get("endpoints", [])) for s in results.get("scraped", [])),
        }}, to=sid)
        print(f"\n[+] Scan complete!")
    except Exception as e:
        import traceback
        print(f"[!] ERROR: {e}\n{traceback.format_exc()}")
        socketio.emit("scan_error", {"msg": str(e)}, to=sid)
    finally:
        sys.stdout = old_stdout
        scan_state["running"] = False

if __name__ == "__main__":
    print("\n🦅 ReconHawk Web UI  →  http://127.0.0.1:5000\n")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
