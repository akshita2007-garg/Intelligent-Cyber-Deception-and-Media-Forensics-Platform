/* IDMF single-page client (vanilla JS, no build step). */
const S = { token: null, user: null, caseId: null, tab: "overview", cache: {} };
const $ = (s, el = document) => el.querySelector(s);
const esc = (t) => String(t ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtBytes = (n) => n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : n > 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B";
const ts = (t) => t ? String(t).replace("T", " ").slice(0, 19) : "—";
const sev = (s) => `<span class="badge sev-${esc(s || "info")}">${esc(s || "info")}</span>`;
const mod = (m) => `<span class="mod mod-${esc(m)}">${esc(m)}</span>`;
const MODCOL = { email: "#4cc9f0", browser: "#7b61ff", network: "#3ddc97", memory: "#ffb020", disk: "#f78c6b", media: "#ff5d9e", deception: "#ff5d73" };
const ENTCOL = { ip: "#9fb3c8", domain: "#c3a6ff", url: "#a0e7e5", email: "#ffd6a5", sha256: "#fdffb6", md5: "#fdffb6", filename: "#caffbf", user: "#ffadad", process: "#bdb2ff", honeytoken: "#ff5d73" };

function toast(msg, ms = 2600) { const t = $("#toast"); t.textContent = msg; t.classList.remove("hidden"); clearTimeout(t._h); t._h = setTimeout(() => t.classList.add("hidden"), ms); }

async function api(path, opts = {}) {
  const headers = opts.headers || {};
  if (S.token) headers.Authorization = "Bearer " + S.token;
  if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.json); }
  const r = await fetch(path, { ...opts, headers });
  if (r.status === 401 && S.token) { logout(); throw new Error("Session expired"); }
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error(data.detail || data || r.statusText);
  return data;
}

/* ---------------- auth ---------------- */
function showLogin() { $("#login").classList.remove("hidden"); $("#app").classList.add("hidden"); }
function logout() { S.token = null; try { sessionStorage.removeItem("idmf"); } catch (e) {} showLogin(); }
async function afterLogin(d) {
  S.token = d.token; S.user = d.username;
  try { sessionStorage.setItem("idmf", JSON.stringify(d)); } catch (e) {}
  $("#login").classList.add("hidden"); $("#app").classList.remove("hidden");
  $("#whoami").textContent = d.username;
  await loadCases();
}
$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try { await afterLogin(await api("/api/auth/login", { method: "POST", json: { username: f.get("username"), password: f.get("password") } })); }
  catch (err) { $("#loginErr").textContent = err.message; }
});
$("#registerBtn").addEventListener("click", async () => {
  const f = new FormData($("#loginForm"));
  try { await afterLogin(await api("/api/auth/register", { method: "POST", json: { username: f.get("username"), password: f.get("password") } })); }
  catch (err) { $("#loginErr").textContent = err.message; }
});
$("#logout").addEventListener("click", (e) => { e.preventDefault(); logout(); });

/* ---------------- cases ---------------- */
async function loadCases() {
  const cases = await api("/api/cases");
  $("#caseList").innerHTML = cases.map((c) => `<li data-id="${c.id}" class="${c.id === S.caseId ? "active" : ""}">
      <div class="cn">${esc(c.name)}</div>
      <div class="cm">${c.evidence_count} items · ${c.modules.join(", ") || "empty"} ${c.integrity_ok ? "" : "· <span class=bad>integrity!</span>"}</div></li>`).join("")
    || `<li class="muted">No cases yet</li>`;
  document.querySelectorAll("#caseList li[data-id]").forEach((li) => li.addEventListener("click", () => openCase(+li.dataset.id)));
  if (!S.caseId && cases.length) openCase(cases[0].id);
  if (!cases.length) { $("#empty").classList.remove("hidden"); $("#caseView").classList.add("hidden"); }
}
$("#newCaseBtn").addEventListener("click", async () => {
  const name = prompt("Case name"); if (!name) return;
  const description = prompt("Short description (optional)") || "";
  const r = await api("/api/cases", { method: "POST", json: { name, description } });
  S.caseId = r.id; await loadCases(); openCase(r.id, "evidence");
});
$("#demoBtn").addEventListener("click", async () => {
  const b = $("#demoBtn"); b.disabled = true; b.innerHTML = `<span class="spin"></span> Building demo…`;
  try {
    const seed = Math.floor(Math.random() * 900) + 100;
    const r = await api(`/api/demo?seed=${seed}`, { method: "POST" });
    S.caseId = r.id; await loadCases(); openCase(r.id); toast("Demo case created from synthetic scenario (seed " + seed + ")");
  } catch (e) { toast(e.message); } finally { b.disabled = false; b.textContent = "Load demo case"; }
});
$("#deleteCaseBtn").addEventListener("click", async () => {
  if (!confirm("Delete this case and its analysis records? Stored evidence files stay in the vault.")) return;
  await api(`/api/cases/${S.caseId}`, { method: "DELETE" }); S.caseId = null; await loadCases();
});
$("#verifyAllBtn").addEventListener("click", async () => {
  const r = await api(`/api/cases/${S.caseId}/verify`, { method: "POST" });
  toast(`${r.ok} of ${r.verified} evidence items match their acquisition SHA-256`); openCase(S.caseId, S.tab);
});

async function openCase(id, tab) {
  S.caseId = id; S.cache = {};
  document.querySelectorAll("#caseList li").forEach((li) => li.classList.toggle("active", +li.dataset.id === id));
  const c = await api(`/api/cases/${id}`);
  S.cache.case = c;
  $("#empty").classList.add("hidden"); $("#caseView").classList.remove("hidden");
  $("#caseTitle").textContent = c.name; $("#caseDesc").textContent = c.description;
  showTab(tab || S.tab || "overview");
}
document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
function showTab(t) {
  S.tab = t;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === t));
  document.querySelectorAll(".tab").forEach((el) => el.classList.toggle("hidden", el.id !== "tab-" + t));
  ({ overview: renderOverview, evidence: renderEvidence, correlation: renderCorrelation, timeline: renderTimeline,
     deception: renderDeception, ai: renderAI, report: renderReport, custody: renderCustody })[t]();
}
async function corr() { if (!S.cache.corr) S.cache.corr = await api(`/api/cases/${S.caseId}/correlation`); return S.cache.corr; }

/* ---------------- overview ---------------- */
async function renderOverview() {
  const c = S.cache.case, el = $("#tab-overview");
  const arts = c.evidence.reduce((a, e) => a + e.artifact_count, 0);
  const sc = c.severity_counts || {};
  const ok = c.evidence.filter((e) => e.integrity_ok).length;
  el.innerHTML = `<div class="grid g4">
    <div class="card stat"><div class="v">${c.evidence.length}</div><div class="l">evidence items</div></div>
    <div class="card stat"><div class="v">${arts}</div><div class="l">artifacts extracted</div></div>
    <div class="card stat"><div class="v">${(sc.high || 0) + (sc.critical || 0)}</div><div class="l">high-severity artifacts</div></div>
    <div class="card stat"><div class="v ${ok === c.evidence.length ? "ok" : "bad"}">${ok}/${c.evidence.length}</div><div class="l">SHA-256 integrity verified</div></div>
  </div>
  <div class="card" style="margin-top:14px"><h3>Platform map</h3><div id="pmap"><p class="muted"><span class="spin"></span> loading…</p></div></div>
  <div class="card" id="ovIncidents" style="margin-top:14px"><h3>Correlated incidents</h3><p class="muted"><span class="spin"></span> correlating…</p></div>`;
  if (!c.evidence.length) { $("#pmap").innerHTML = "<p class=muted>Upload evidence on the Evidence tab, or load the demo case.</p>"; $("#ovIncidents").innerHTML = ""; return; }
  const [L, k, ins] = await Promise.all([api(`/api/cases/${S.caseId}/layers`), corr(), insights()]);
  const cnt = (o) => Object.entries(o).map(([n, v]) => `<span class="pill ${v ? "on" : ""}">${n} <b>${v}</b></span>`).join("");
  $("#pmap").innerHTML = `<div class="layer top" data-go="evidence"><div class="ln">Investigator dashboard</div><div class="lm">Case management · Evidence uploads · Investigation results</div></div>
    <div class="arrow">↓</div>
    <div class="layer-grid">
      <div class="layer l-forensic" data-go="evidence"><div class="ln">Forensic modules</div><div class="lm">${cnt(L.forensic_modules)}</div></div>
      <div class="layer l-media" data-go="evidence"><div class="ln">Media forensics</div><div class="lm">${cnt(L.media)}<span class="pill">deepfake <b>not bundled</b></span></div></div>
      <div class="layer l-deception" data-go="deception"><div class="ln">Cyber deception</div><div class="lm"><span class="pill ${L.deception.honeypot_logs ? "on" : ""}">honeypot logs <b>${L.deception.honeypot_logs}</b></span><span class="pill ${L.deception.honeytokens ? "on" : ""}">honeytokens <b>${L.deception.honeytokens}</b></span><span class="pill ${L.deception.decoy_events ? "on" : ""}">decoy events <b>${L.deception.decoy_events}</b></span></div></div>
      <div class="layer l-ai" data-go="ai"><div class="ln">AI assistance</div><div class="lm"><span class="pill on">summaries <b>${ins.evidence_summaries.length + 1}</b></span><span class="pill on">insights <b>${ins.items.length}</b></span><span class="pill ${ins.llm_configured ? "on" : ""}">LLM <b>${ins.llm_configured ? "on" : "off"}</b></span></div></div>
    </div>
    <div class="arrow">↓</div>
    <div class="layer l-core" data-go="correlation"><div class="ln">Common evidence processing and correlation engine</div><div class="lm"><span class="pill on">entities <b>${k.stats.entities}</b></span><span class="pill on">pivots <b>${k.stats.pivot_entities}</b></span><span class="pill on">links <b>${k.stats.links}</b></span><span class="pill on">incidents <b>${k.stats.incidents}</b></span><span class="pill ${k.stats.honeytoken_hits ? "on" : ""}">tripwire hits <b>${k.stats.honeytoken_hits}</b></span><span class="pill on">timeline events <b>${k.timeline.length}</b></span></div></div>
    <div class="arrow">↓</div>
    <div class="layer l-report" data-go="report"><div class="ln">Unified forensic investigation report</div><div class="lm">${L.report_ready ? '<span class="pill on">report generated</span>' : '<span class="pill">not generated yet</span>'} Evidence references · Findings · Timeline · AI-assisted narrative · PDF export</div></div>`;
  document.querySelectorAll("#pmap [data-go]").forEach((d) => d.onclick = () => showTab(d.dataset.go));
  const byId = Object.fromEntries(k.evidence.map((e) => [e.id, e]));
  $("#ovIncidents").innerHTML = `<h3>Correlated incidents</h3>` + (k.incidents.map((i) => `
    <div style="margin-bottom:12px"><b>Incident ${i.id}</b> <span class="muted">· ${i.evidence_ids.length} items · ${ts(i.first_seen)} → ${ts(i.last_seen)}</span>
      <div style="margin:6px 0">${i.evidence_ids.map((e) => `${mod(byId[e].module)} <span class="mono">E${e}</span> ${esc(byId[e].filename)}`).join("<br>")}</div>
      <div>${i.key_entities.slice(0, 5).map((x) => `<span class="chip"><b>${x.type}</b>${esc(x.value)}</span>`).join("")}</div></div>`).join("")
    || "<p class=muted>No cross-evidence links above the threshold.</p>") +
    (k.honeytoken_hits.length ? `<p class="bad">⚑ ${k.honeytoken_hits.length} honeytoken tripwire hit(s) — see Deception tab.</p>` : "");
}
async function insights() { if (!S.cache.ins) S.cache.ins = await api(`/api/cases/${S.caseId}/ai/insights`); return S.cache.ins; }

/* ---------------- AI assistance ---------------- */
async function renderAI() {
  const el = $("#tab-ai"); el.innerHTML = `<p class="muted"><span class="spin"></span> generating summaries and insights…</p>`;
  const ins = await insights();
  const byKind = (k) => ins.items.filter((i) => i.kind === k);
  const cites = (t) => esc(t).replace(/\[E(\d+)(:[0-9a-f]+)?\]/g, (m, id) => `<span class="cite" data-id="${id}">${m}</span>`);
  const vmark = (st) => st === "verified" ? `<span class="vok" title="every identifier and time checked against the cited evidence">✔ verified</span>` : `<span class="vstat">✖ ${esc(st)}</span>`;
  el.innerHTML = `<div class="card"><div class="row"><h3 style="margin:0">Ask about this case</h3><span class="spacer"></span><span class="muted" style="font-size:12px">${ins.llm_configured ? "LLM answers, verified sentence by sentence" : "Evidence search (set IDMF_LLM_PROVIDER / IDMF_LLM_API_KEY for written answers)"}</span></div>
      <form id="askForm" class="row" style="margin-top:10px"><input id="askQ" placeholder="e.g. Did the attacker use the decoy credential?  Which evidence shows C2 beaconing?" style="flex:1;width:auto"><button class="primary">Ask</button></form>
      <div id="askOut"></div></div>
    <div class="grid g2" style="margin-top:14px">
      <div class="card"><h3>Case summary</h3>${ins.summary.map((s) => `<div class="sent ${s.status === "verified" ? "" : "unverified"}">${cites(s.text)}</div>`).join("")}</div>
      <div class="card"><h3>Recommended next steps <span class="muted" style="font-weight:400;font-size:12px">(suggestions, not findings)</span></h3><ol style="margin:0;padding-left:18px">${ins.recommendations.map((r) => `<li style="margin:6px 0">${esc(r)}</li>`).join("") || "<li class=muted>No recommendations.</li>"}</ol></div>
    </div>
    <div class="card" style="margin-top:14px"><h3>Attack chain — MITRE ATT&amp;CK mapping</h3>
      <div class="chain">${ins.attack_chain.map((st) => `<div class="stage"><div class="st">${esc(st.tactic)}</div><div class="sd">${st.techniques.map((t) => `<span class="chip">${t.id}</span>`).join("")}</div><div class="sm">${ts(st.first_seen)}</div></div>`).join('<div class="sa">→</div>') || "<p class=muted>No ATT&CK-mapped activity.</p>"}</div>
      ${byKind("attack_chain").map((i) => `<div class="sent">${cites(i.text)} ${vmark(i.verification)}</div>`).join("")}</div>
    <div class="grid g2" style="margin-top:14px">
      <div class="card"><div class="row"><h3 style="margin:0">Pivot indicators</h3><span class="spacer"></span><a href="/api/cases/${S.caseId}/iocs.csv?token=${S.token}"><button class="small">Export IOC CSV</button></a></div>
        <table style="margin-top:8px"><thead><tr><th>Indicator</th><th>Items</th><th>Weight</th></tr></thead><tbody>${ins.pivots.map((p) => `<tr><td><span class="chip"><b>${p.type}</b>${esc(p.value)}</span></td><td>${p.evidence_ids.map((i) => `<span class="cite" data-id="${i}">E${i}</span>`).join(" ")}</td><td>${p.weight}</td></tr>`).join("") || `<tr><td colspan=3 class=muted>No pivots.</td></tr>`}</tbody></table></div>
      <div class="card"><h3>Deception, media and review insights</h3>${["deception", "media", "review"].flatMap(byKind).map((i) => `<div class="sent ${i.severity === "high" || i.severity === "critical" ? "hot" : ""}"><b>${esc(i.title)}</b><br>${cites(i.text)} ${vmark(i.verification)}</div>`).join("") || "<p class=muted>None.</p>"}</div>
    </div>
    <div class="card" style="margin-top:14px"><h3>Evidence summaries</h3>${ins.evidence_summaries.map((e) => `<div class="sent">${mod(e.module)} ${cites(e.text)}</div>`).join("")}</div>`;
  el.querySelectorAll(".cite").forEach((c) => c.onclick = () => showEvidence(+c.dataset.id));
  $("#askForm").onsubmit = async (ev) => {
    ev.preventDefault(); const q = $("#askQ").value.trim(); if (!q) return;
    $("#askOut").innerHTML = `<p class="muted"><span class="spin"></span> searching evidence…</p>`;
    const r = await api(`/api/cases/${S.caseId}/ai/ask`, { method: "POST", json: { question: q } });
    $("#askOut").innerHTML = `${r.note ? `<p class="muted" style="font-size:12px">${esc(r.note)}</p>` : ""}${r.answer.map((s) => `<div class="sent ${s.status === "verified" || s.status === "info" ? "" : "unverified"}">${cites(s.text)} ${s.status === "info" ? "" : vmark(s.status)}</div>`).join("")}`;
    $("#askOut").querySelectorAll(".cite").forEach((c) => c.onclick = () => showEvidence(+c.dataset.id));
  };
}

/* ---------------- evidence ---------------- */
async function renderEvidence() {
  const c = await api(`/api/cases/${S.caseId}`); S.cache.case = c;
  const el = $("#tab-evidence");
  el.innerHTML = `<div class="card"><div class="drop" id="drop">Drop evidence files here or <a href="#" id="pick">browse</a><br>
      <span style="font-size:12px">.eml/.mbox · Chrome/Firefox history · .pcap/.pcapng · memory/disk images · TSK body files · images/video · Cowrie JSON</span>
      <div class="row" style="justify-content:center;margin-top:10px"><label style="margin:0">Module <select id="modSel" style="width:auto">
        <option value="">auto-detect</option><option>email</option><option>browser</option><option>network</option><option>memory</option><option>disk</option><option>media</option><option>deception</option></select></label></div>
      <input type="file" id="fileIn" multiple hidden></div><p id="upStatus" class="muted"></p></div>
    <div class="card" style="margin-top:14px;overflow:auto"><table><thead><tr><th>ID</th><th>File</th><th>Module</th><th>Size</th><th>SHA-256 (acquisition)</th><th>Integrity</th><th>Artifacts</th><th>Severity</th><th>ms</th></tr></thead><tbody>
    ${c.evidence.map((e) => `<tr class="click" data-id="${e.id}"><td class="mono">E${e.id}</td><td>${esc(e.filename)}${e.status === "error" ? `<div class=bad style="font-size:11px">${esc(e.error)}</div>` : ""}</td><td>${mod(e.module)}</td><td>${fmtBytes(e.size)}</td>
      <td class="mono" title="${e.sha256}">${e.sha256.slice(0, 16)}…</td><td class="${e.integrity_ok ? "ok" : "bad"}">${e.integrity_ok ? "✔ verified" : "✖ mismatch"}</td>
      <td>${e.artifact_count}</td><td>${sev(e.summary.max_severity)}</td><td class="muted">${(e.analysis_seconds * 1000).toFixed(0)}</td></tr>`).join("") || `<tr><td colspan=9 class=muted>No evidence yet.</td></tr>`}
    </tbody></table></div>`;
  const drop = $("#drop"), fin = $("#fileIn");
  $("#pick").onclick = (e) => { e.preventDefault(); fin.click(); };
  fin.onchange = () => upload(fin.files);
  drop.ondragover = (e) => { e.preventDefault(); drop.classList.add("over"); };
  drop.ondragleave = () => drop.classList.remove("over");
  drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove("over"); upload(e.dataTransfer.files); };
  el.querySelectorAll("tr.click").forEach((tr) => tr.addEventListener("click", () => showEvidence(+tr.dataset.id)));
}
async function upload(files) {
  if (!files.length) return;
  const fd = new FormData(); [...files].forEach((f) => fd.append("files", f)); fd.append("module", $("#modSel").value);
  $("#upStatus").innerHTML = `<span class="spin"></span> Hashing, storing and analysing ${files.length} file(s)…`;
  try { const r = await api(`/api/cases/${S.caseId}/evidence`, { method: "POST", body: fd }); toast(`${r.length} item(s) acquired and analysed`); S.cache = {}; await loadCases(); renderEvidence(); }
  catch (e) { $("#upStatus").textContent = e.message; }
}
async function showEvidence(id) {
  const e = await api(`/api/evidence/${id}`);
  const media = e.module === "media" && e.artifacts[0] && e.artifacts[0].detail.score !== undefined ? e.artifacts[0].detail : null;
  const a0 = e.artifacts[0] || { detail: {} };
  const audio = a0.kind === "media.audio" && a0.detail.format === "WAV" ? a0.detail : null;
  const video = a0.kind === "media.video" ? a0.detail : null;
  $("#drawerBody").innerHTML = `<div class="row">${mod(e.module)}<h2 style="margin:0">E${e.id} · ${esc(e.filename)}</h2></div>
    <div class="kv" style="margin:14px 0">
      <div>SHA-256 (acquired)</div><div class="mono">${e.sha256}</div><div>MD5</div><div class="mono">${e.md5}</div>
      <div>Size</div><div>${fmtBytes(e.size)}</div><div>Acquired</div><div>${ts(e.uploaded_at)} by ${esc(e.uploaded_by)}</div>
      <div>Last verified</div><div class="${e.integrity_ok ? "ok" : "bad"}">${ts(e.last_verified_at)} · ${e.integrity_ok ? "hash matches" : "HASH MISMATCH"}</div>
      ${Object.entries(e.summary).filter(([k]) => !["max_severity"].includes(k)).map(([k, v]) => `<div>${esc(k.replace(/_/g, " "))}</div><div>${esc(typeof v === "object" ? JSON.stringify(v) : v)}</div>`).join("")}
    </div>
    <div class="row"><button class="small" id="dvVerify">Re-verify hash</button>
      <select id="dvMod" style="width:auto"><option value="">re-run as…</option>${Object.keys(MODCOL).map((m) => `<option>${m}</option>`).join("")}</select>
      <a class="small" href="/api/evidence/${e.id}/raw?token=${S.token}">Export original</a></div>
    ${media ? `<h3>Media analysis</h3><p>Fused manipulation score <b>${media.score.toFixed(2)}</b> (threshold ${media.threshold}) — <b>${esc(media.verdict)}</b></p>
      <div class="score"><i style="left:${media.score * 100}%"></i></div>
      <div class="grid g2"><div><img class="ela" src="/api/evidence/${e.id}/ela?token=${S.token}" alt="Error level analysis map"><p class="muted" style="font-size:12px">Error-level analysis map (bright = higher re-compression error)</p></div>
      <div class="kv">${Object.entries(media.features).map(([k, v]) => `<div>${esc(k)}</div><div class="mono">${v}</div>`).join("")}<div>JPEG quality</div><div>${media.jpeg_quality ?? "—"}</div></div></div>` : ""}
    ${audio ? `<h3>Audio analysis</h3><p><b>${esc(audio.verdict)}</b> · ${audio.duration_s} s · ${audio.sample_rate} Hz · ${audio.bits}-bit · peak ${audio.peak_dbfs} dBFS · RMS ${audio.rms_dbfs} dBFS</p>
      ${audio.waveform_image ? `<img class="ela" src="/api/evidence/${e.id}/ela?token=${S.token}" alt="Waveform with splice candidates"><p class="muted" style="font-size:12px">Waveform; red lines mark splice candidates</p>` : ""}
      <div class="kv"><div>splice candidates</div><div class="mono">${audio.splice_candidates.map((x) => x.time_s + " s").join(", ") || "none"}</div><div>level jumps</div><div class="mono">${audio.level_jumps.map((x) => x.time_s + " s").join(", ") || "none"}</div>
      <div>clipping</div><div>${(audio.clipping_ratio * 100).toFixed(2)}%</div><div>low-pass wall</div><div>${audio.lowpass_wall_hz ? audio.lowpass_wall_hz + " Hz" : "none"}</div><div>metadata</div><div class="mono">${esc(JSON.stringify(audio.tags))}</div></div>` : ""}
    ${video ? `<h3>Video analysis</h3><div class="kv"><div>codec / resolution</div><div>${esc(video.codec || "—")} · ${esc(video.resolution || "—")}</div><div>frames examined</div><div>${video.temporal.frames_examined ?? "OpenCV not installed"}</div>
      <div>duplicated-frame runs</div><div class="mono">${(video.temporal.duplicate_runs || []).map((r) => `${r.length} frames ending at ${r.end_frame}`).join(", ") || "none"}</div>
      <div>abrupt changes</div><div class="mono">${(video.temporal.abrupt_changes || []).map((r) => `frame ${r.frame}${r.time_s !== null ? " (" + r.time_s + " s)" : ""}`).join(", ") || "none"}</div><div>deepfake model</div><div>${esc(video.deepfake)}</div></div>` : ""}
    <h3>Artifacts (${e.artifacts.length})</h3>
    <table><thead><tr><th>Time (UTC)</th><th>Kind</th><th>Finding</th><th>Severity</th></tr></thead><tbody>
    ${e.artifacts.slice(0, 400).map((a) => `<tr><td class="mono" style="white-space:nowrap">${ts(a.ts)}</td><td class="mono">${esc(a.kind)}</td>
      <td>${esc(a.title)}${a.indicators.map((i) => `<div class="ind">⚠ ${esc(i)}</div>`).join("")}
      <div>${a.entities.slice(0, 8).map((x) => `<span class="chip"><b>${x.type}</b>${esc(x.value)}</span>`).join("")}</div></td><td>${sev(a.severity)}</td></tr>`).join("")}
    </tbody></table>`;
  $("#drawer").classList.remove("hidden");
  $("#dvVerify").onclick = async () => { const r = await api(`/api/evidence/${id}/verify`, { method: "POST" }); toast(r.integrity_ok ? "Hash matches acquisition value" : "HASH MISMATCH"); showEvidence(id); };
  $("#dvMod").onchange = async (ev) => { if (!ev.target.value) return; await api(`/api/evidence/${id}/reanalyse?module=${ev.target.value}`, { method: "POST" }); S.cache = {}; showEvidence(id); };
}
$("#drawerClose").onclick = () => $("#drawer").classList.add("hidden");
$("#drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") $("#drawer").classList.add("hidden"); });

/* ---------------- correlation ---------------- */
async function renderCorrelation() {
  const el = $("#tab-correlation"); el.innerHTML = `<p class="muted"><span class="spin"></span> correlating…</p>`;
  const k = await corr(); const byId = Object.fromEntries(k.evidence.map((e) => [e.id, e]));
  el.innerHTML = `<div class="grid g4">
      <div class="card stat"><div class="v">${k.stats.entities}</div><div class="l">normalised entities</div></div>
      <div class="card stat"><div class="v">${k.stats.pivot_entities}</div><div class="l">pivot entities (in ≥2 items)</div></div>
      <div class="card stat"><div class="v">${k.stats.links}</div><div class="l">links ≥ θ=${k.params.threshold}</div></div>
      <div class="card stat"><div class="v">${k.stats.incidents}</div><div class="l">incidents · ${k.stats.seconds}s</div></div></div>
    <div class="graph-wrap" style="margin-top:14px"><canvas id="graph"></canvas></div>
    <div class="legend">${Object.entries(MODCOL).map(([m, c]) => `<i class="dot" style="background:${c}"></i>${m}`).join("")} <i class="dot" style="background:#9fb3c8"></i>shared entity <i class="dot" style="background:#ff5d73;border-radius:0"></i>honeytoken <em class="muted">· drag nodes · double-click evidence to open · unlinked items on the right</em></div>
    <div class="card" style="margin-top:14px;overflow:auto"><h3>Cross-evidence links</h3><table><thead><tr><th>Score</th><th>Evidence pair</th><th>Shared entities (weight)</th><th>Δt</th></tr></thead><tbody>
      ${k.links.map((l) => `<tr><td><b>${l.score.toFixed(2)}</b>${l.tripwire ? ` <span class="badge sev-high">tripwire</span>` : ""}</td>
        <td>${mod(byId[l.source].module)} E${l.source} ${esc(byId[l.source].filename)}<br>${mod(byId[l.target].module)} E${l.target} ${esc(byId[l.target].filename)}</td>
        <td>${l.shared.slice(0, 6).map((s) => `<span class="chip"><b>${s.type}</b>${esc(s.value)} <span class=muted>${s.weight}</span></span>`).join("")}</td>
        <td class="muted">${l.min_gap_min === null ? "—" : l.min_gap_min + " min"}</td></tr>`).join("") || `<tr><td colspan=4 class=muted>No links above threshold.</td></tr>`}
    </tbody></table><p class="muted" style="font-size:12px">Score = Σ type-weight × log((N+1)/df) × temporal boost (×${1 + k.params.beta} within ${k.params.window_min} min), with allowlisted, popular and own-organisation identifiers suppressed; honeytoken hits always link.</p></div>`;
  drawGraph($("#graph"), k.graph);
}
function drawGraph(cv, g) {
  const W = cv.clientWidth, H = cv.clientHeight, dpr = window.devicePixelRatio || 1;
  cv.width = W * dpr; cv.height = H * dpr; const ctx = cv.getContext("2d"); ctx.scale(dpr, dpr);
  const nodes = g.nodes.map((n, i) => ({ ...n, x: W / 2 + Math.cos(i) * 200 * Math.random(), y: H / 2 + Math.sin(i) * 160 * Math.random(), vx: 0, vy: 0 }));
  const idx = Object.fromEntries(nodes.map((n, i) => [n.id, i]));
  const edges = g.edges.filter((e) => e.source in idx && e.target in idx).map((e) => [idx[e.source], idx[e.target]]);
  let hover = null, drag = null;
  // Fruchterman-Reingold layout with cooling; unlinked evidence drifts to the rim
  const k = 0.55 * Math.sqrt((W * H) / Math.max(1, nodes.length));
  const deg = nodes.map(() => 0); edges.forEach(([s, t]) => { deg[s]++; deg[t]++; });
  function step(temp) {
    for (const n of nodes) { n.vx = 0; n.vy = 0; }
    for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {
      const p = nodes[i], q = nodes[j]; const dx = p.x - q.x, dy = p.y - q.y, d = Math.sqrt(dx * dx + dy * dy) + 0.01;
      const f = (k * k) / d; p.vx += (dx / d) * f; p.vy += (dy / d) * f; q.vx -= (dx / d) * f; q.vy -= (dy / d) * f;
    }
    for (const [s, t] of edges) { const p = nodes[s], q = nodes[t]; const dx = p.x - q.x, dy = p.y - q.y, d = Math.sqrt(dx * dx + dy * dy) + 0.01;
      const f = (d * d) / k; p.vx -= (dx / d) * f; p.vy -= (dy / d) * f; q.vx += (dx / d) * f; q.vy += (dy / d) * f; }
    nodes.forEach((n, i) => {
      const g = deg[i] ? 0.02 : 0.005; n.vx += (W / 2 - n.x) * g * k / 10; n.vy += (H / 2 - n.y) * g * k / 10;
      if (n === drag || n.fixed) return;
      const m = Math.sqrt(n.vx * n.vx + n.vy * n.vy) + 0.01; n.x += (n.vx / m) * Math.min(m, temp); n.y += (n.vy / m) * Math.min(m, temp);
      n.x = Math.max(30, Math.min(W - 400, n.x)); n.y = Math.max(24, Math.min(H - 24, n.y));
    });
  }
  // unlinked evidence goes to a lane on the right; the rest is laid out by force
  const lane = W - 190; let ly = 40;
  nodes.forEach((n, i) => { if (!deg[i]) { n.fixed = true; n.x = lane; n.y = ly; ly += 30; } else { n.x = 60 + Math.random() * (lane - 160); } });
  for (let it = 0; it < 300; it++) step((W / 8) * (1 - it / 300) + 0.5);
  function draw() {
    ctx.clearRect(0, 0, W, H);
    if (nodes.some((n) => n.fixed)) { ctx.fillStyle = "#121925"; ctx.fillRect(lane - 20, 0, W - lane + 20, H); ctx.fillStyle = "#8b95a7"; ctx.font = "11px Inter, system-ui"; ctx.fillText("UNLINKED EVIDENCE", lane - 8, 20); }
    ctx.strokeStyle = "#2a3446"; ctx.lineWidth = 1;
    for (const [s, t] of edges) { ctx.beginPath(); ctx.moveTo(nodes[s].x, nodes[s].y); ctx.lineTo(nodes[t].x, nodes[t].y);
      ctx.strokeStyle = hover !== null && (s === hover || t === hover) ? "#4cc9f0" : "#2a3446"; ctx.stroke(); }
    nodes.forEach((n, i) => {
      const ev = n.kind === "evidence"; ctx.beginPath();
      if (n.kind === "honeytoken") ctx.rect(n.x - 7, n.y - 7, 14, 14); else ctx.arc(n.x, n.y, ev ? 11 : 5, 0, 7);
      ctx.fillStyle = ev ? MODCOL[n.module] || "#888" : ENTCOL[n.kind] || "#9fb3c8"; ctx.fill();
      if (ev || i === hover) { ctx.fillStyle = "#e6e9ef"; ctx.font = (ev ? "600 " : "") + "11px Inter, system-ui"; ctx.fillText((ev ? n.id + " " : n.kind + ": ") + String(n.label).slice(0, ev ? 24 : 40), n.x + 13, n.y + 4); }
    });
  }
  function pick(e) { const r = cv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    let best = null, bd = 196; nodes.forEach((n, i) => { const d = (n.x - x) ** 2 + (n.y - y) ** 2; if (d < bd) { bd = d; best = i; } }); return [best, x, y]; }
  cv.onmousemove = (e) => { const [b, x, y] = pick(e); if (drag) { drag.x = x; drag.y = y; for (let i = 0; i < 3; i++) step(2); } hover = b; draw(); };
  cv.onmousedown = (e) => { const [b] = pick(e); if (b !== null) drag = nodes[b]; };
  cv.onmouseup = () => { drag = null; };
  cv.ondblclick = (e) => { const [b] = pick(e); if (b !== null && nodes[b].kind === "evidence") showEvidence(+nodes[b].id.slice(1)); };
  draw();
}

/* ---------------- timeline ---------------- */
async function renderTimeline() {
  const el = $("#tab-timeline"); const k = await corr(); const byId = Object.fromEntries(k.evidence.map((e) => [e.id, e]));
  const draw = () => {
    const f = $("#tlFilter").value, m = $("#tlMod").value;
    const rows = k.timeline.filter((r) => (f === "all" || (f === "pivot" && r.pivot) || (f === "sus" && ["medium", "high", "critical"].includes(r.severity)) || (f === "both" && (r.pivot || ["medium", "high", "critical"].includes(r.severity)))) && (!m || r.module === m));
    let day = ""; $("#tlList").innerHTML = rows.slice(0, 1500).map((r) => { const d = r.ts.slice(0, 10); const h = d !== day ? `<div class="tl-day">${d}</div>` : ""; day = d;
      return `${h}<div class="tl-item sev-${r.severity} ${r.pivot ? "pivot" : ""}"><span class="tl-time">${r.ts.slice(11, 19)}</span> ${mod(r.module)} <span class="mono muted">E${r.evidence_id}</span> ${esc(r.title)} ${r.pivot ? '<span class="badge" style="color:var(--accent);border-color:#24506a">pivot</span>' : ""}</div>`; }).join("") || "<p class=muted>No events.</p>";
    $("#tlCount").textContent = `${rows.length} of ${k.timeline.length} events`;
  };
  el.innerHTML = `<div class="card"><div class="row"><label style="margin:0">Show <select id="tlFilter" style="width:auto"><option value="both">suspicious + pivot</option><option value="pivot">pivot events only</option><option value="sus">medium/high severity</option><option value="all">all events</option></select></label>
    <label style="margin:0">Module <select id="tlMod" style="width:auto"><option value="">all</option>${Object.keys(MODCOL).map((m) => `<option>${m}</option>`).join("")}</select></label><span class="spacer"></span><span class="muted" id="tlCount"></span></div>
    <p class="muted" style="font-size:12px">Unified UTC timeline across all evidence. <b>Pivot</b> events contain an entity that links this item to another item.</p>
    <div class="tl" id="tlList"></div></div>`;
  $("#tlFilter").onchange = draw; $("#tlMod").onchange = draw; draw();
}

/* ---------------- deception ---------------- */
async function renderDeception() {
  const el = $("#tab-deception");
  const [hts, evs, k] = await Promise.all([api(`/api/cases/${S.caseId}/honeytokens`), api(`/api/cases/${S.caseId}/deception-events`), corr()]);
  const byId = Object.fromEntries(k.evidence.map((e) => [e.id, e]));
  el.innerHTML = `<div class="grid g2">
    <div class="card"><h3>Create honeytoken</h3>
      <p class="muted" style="font-size:12px">Decoy values have no legitimate use, so any appearance in later evidence or any decoy interaction is a high-confidence intrusion signal. Every evidence item is swept for them, including raw bytes of disk and memory images.</p>
      <div class="row"><select id="htType" style="width:auto"><option value="credential">credential</option><option value="api_key">cloud API key</option><option value="canary_url">canary URL</option><option value="email">honey e-mail address</option><option value="document">decoy document name</option></select>
      <input id="htLabel" placeholder="label (optional)" style="flex:1;width:auto"></div>
      <input id="htPlace" placeholder="where it will be planted, e.g. \\\\fs01\\it\\Passwords.txt (tokens with the same location form one decoy set)" style="margin-top:8px">
      <div class="row" style="margin-top:10px"><button class="primary" id="htCreate">Generate</button>
      ${hts.length ? `<a href="/api/cases/${S.caseId}/honeytokens/decoy-document?token=${S.token}">Download decoy document</a>` : ""}</div></div>
    <div class="card"><h3>Live decoys served by this platform</h3>
      <p><a href="/decoy/admin" target="_blank">/decoy/admin</a> — decoy admin login page; any visit or sign-in is logged (a honeytoken username is matched automatically).</p>
      <p>Canary URLs (<span class="mono">/decoy/t/…</span>) — any request is logged with source IP and user agent.</p>
      <p class="muted" style="font-size:12px">Captured interactions can be snapshotted into a hashed evidence item and then flow through correlation and reporting like any other evidence.</p>
      <button id="impEv" ${evs.length ? "" : "disabled"}>Import ${evs.length} captured event(s) as evidence</button></div></div>
  <div class="card" style="margin-top:14px;overflow:auto"><h3>Honeytokens (${hts.length})</h3><table><thead><tr><th>#</th><th>Type</th><th>Label</th><th>Value</th><th>Secret</th><th>Planted at</th></tr></thead><tbody>
    ${hts.map((h) => `<tr><td>${h.id}</td><td>${esc(h.token_type)}</td><td>${esc(h.label)}</td><td class="mono">${esc(h.value)}</td><td class="mono"><span class="reveal" data-s="${esc(h.secret)}">${h.secret ? "•••••• (click)" : "—"}</span></td><td class="muted">${esc(h.placed_at)}</td></tr>`).join("") || `<tr><td colspan=6 class=muted>None yet.</td></tr>`}</tbody></table></div>
  <div class="card" style="margin-top:14px;overflow:auto"><h3>Tripwire hits in evidence (${k.honeytoken_hits.length})</h3><table><thead><tr><th>Honeytoken</th><th>Evidence</th><th>Where</th><th>Time</th></tr></thead><tbody>
    ${k.honeytoken_hits.map((h) => `<tr><td>${esc(h.label)} <span class="muted">(${h.token_type}, ${h.matched})</span></td><td>${mod(byId[h.evidence_id].module)} E${h.evidence_id} ${esc(byId[h.evidence_id].filename)}</td><td>${esc(h.artifact_title)}</td><td class="mono">${ts(h.ts)}</td></tr>`).join("") || `<tr><td colspan=4 class=muted>No honeytoken found in evidence.</td></tr>`}</tbody></table></div>
  <div class="card" style="margin-top:14px;overflow:auto"><h3>Captured decoy interactions (${evs.length})</h3><table><thead><tr><th>Time (UTC)</th><th>Decoy</th><th>Source</th><th>Detail</th></tr></thead><tbody>
    ${evs.map((v) => `<tr><td class="mono">${ts(v.ts)}</td><td>${esc(v.decoy)}${v.honeytoken_id ? ' <span class="badge sev-high">honeytoken</span>' : ""}</td><td class="mono">${esc(v.src_ip)}<div class="muted" style="font-size:11px">${esc(v.user_agent.slice(0, 60))}</div></td><td class="mono" style="font-size:11px">${esc(JSON.stringify(v.detail))}</td></tr>`).join("") || `<tr><td colspan=4 class=muted>No interactions captured yet.</td></tr>`}</tbody></table></div>`;
  $("#htCreate").onclick = async () => { await api(`/api/cases/${S.caseId}/honeytokens`, { method: "POST", json: { token_type: $("#htType").value, label: $("#htLabel").value, placed_at: $("#htPlace").value } }); S.cache = {}; renderDeception(); };
  $("#impEv").onclick = async () => { await api(`/api/cases/${S.caseId}/deception-events/import`, { method: "POST" }); toast("Decoy events imported as evidence"); S.cache = {}; await loadCases(); renderDeception(); };
  el.querySelectorAll(".reveal").forEach((s) => s.onclick = () => { s.textContent = s.dataset.s || "—"; });
}

/* ---------------- report ---------------- */
async function renderReport(rep) {
  const el = $("#tab-report");
  el.innerHTML = `<div class="card"><div class="row"><button class="primary" id="genRep">Generate report</button>
      <label class="row" style="margin:0;color:var(--text)"><input type="checkbox" id="useLlm" style="width:auto"> Use LLM narrative (if configured)</label>
      <span class="spacer"></span>${rep ? `<a href="/api/cases/${S.caseId}/report.pdf?token=${S.token}" target="_blank"><button>Download PDF</button></a>` : ""}</div>
      <p class="muted" style="font-size:12px">Every sentence must cite evidence as [E&lt;id&gt;:&lt;sha-prefix&gt;]. A verifier checks that cited items exist and that every IP, domain, e-mail, URL, hash and timestamp in the sentence appears in the cited evidence.</p></div>
    <div id="repBody"></div>`;
  $("#genRep").onclick = async () => { $("#genRep").innerHTML = `<span class="spin"></span> Generating…`; const r = await api(`/api/cases/${S.caseId}/report`, { method: "POST", json: { use_llm: $("#useLlm").checked } }); S.cache.report = r; renderReport(r); };
  rep = rep || S.cache.report; if (!rep) return;
  const v = rep.verification;
  $("#repBody").innerHTML = `<div class="grid g4" style="margin-top:14px">
      <div class="card stat"><div class="v">${v.sentences}</div><div class="l">statements</div></div>
      <div class="card stat"><div class="v ${v.traceability === 1 ? "ok" : "bad"}">${(v.traceability * 100).toFixed(1)}%</div><div class="l">verified against cited evidence</div></div>
      <div class="card stat"><div class="v">${rep.evidence.length}</div><div class="l">evidence items cited</div></div>
      <div class="card stat"><div class="v" style="font-size:16px">${esc(rep.generator)}</div><div class="l">generator · ${ts(rep.generated_at)}</div></div></div>
    ${rep.note ? `<p class="muted">${esc(rep.note)}</p>` : ""}
    ${rep.recommendations && rep.recommendations.length ? `<div class="card" style="margin-top:14px"><h3>Recommended next steps <span class="muted" style="font-weight:400;font-size:12px">(suggestions from the AI assistance layer)</span></h3><ol style="margin:0;padding-left:18px">${rep.recommendations.map((r) => `<li style="margin:5px 0">${esc(r)}</li>`).join("")}</ol></div>` : ""}
    <div class="card" style="margin-top:14px">${rep.sections.map((s) => `<div class="report-sec"><h3>${esc(s.title)}</h3>
      ${s.sentences.map((x) => `<div class="sent ${x.status === "verified" ? "" : "unverified"}">${esc(x.text).replace(/\[E(\d+)(:[0-9a-f]+)?\]/g, (m, id) => `<span class="cite" data-id="${id}">${m}</span>`)}
        ${x.status !== "verified" ? `<div class="vstat">✖ ${esc(x.status)}: ${esc(x.reason)}</div>` : ""}</div>`).join("")}</div>`).join("")}</div>`;
  $("#repBody").querySelectorAll(".cite").forEach((c) => c.onclick = () => showEvidence(+c.dataset.id));
}

/* ---------------- custody ---------------- */
async function renderCustody() {
  const r = await api(`/api/cases/${S.caseId}/audit`);
  $("#tab-custody").innerHTML = `<div class="card"><p class="${r.chain_ok ? "ok" : "bad"}"><b>${r.chain_ok ? "✔ Audit hash chain intact" : "✖ Audit chain broken at entry " + r.first_bad_entry}</b>
      <span class="muted"> — every entry stores SHA-256(previous hash ‖ entry), so editing or deleting any past entry breaks the chain.</span></p>
    <div style="overflow:auto"><table><thead><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Detail</th><th>Entry hash</th></tr></thead><tbody>
    ${r.entries.map((a) => `<tr><td>${a.id}</td><td class="mono">${ts(a.ts)}</td><td>${esc(a.actor)}</td><td class="mono">${esc(a.action)}</td><td style="font-size:12px">${esc(a.detail)}</td><td class="mono" title="prev ${a.prev_hash}">${a.entry_hash.slice(0, 16)}…</td></tr>`).join("")}
    </tbody></table></div></div>`;
}

/* ---------------- boot ---------------- */
(async () => {
  let saved = null; try { saved = JSON.parse(sessionStorage.getItem("idmf") || "null"); } catch (e) {}
  if (saved) { S.token = saved.token; try { await api("/api/me"); return afterLogin(saved); } catch (e) {} }
  showLogin();
})();
