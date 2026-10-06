import "./theme.css";
import { invoke } from "@tauri-apps/api/core";

type View = "source" | "scan" | "results" | "forensics" | "audit" | "image" | "hex";

const state = {
  view: "source" as View,
  image: "",
  outdir: "recovered",
  log: "",
  scanning: false,
  results: [] as { fn: string; off: number; size: number; chopped: boolean; sha: string }[],
  mft: [] as { off: number; num: number; seq: number; isDir: boolean; name: string; deleted: boolean; fs: string; size: number; date: string }[],
  audit: "",
  preview: null as null | { fn: string; b64: string; size: number; truncated: boolean },
  csrc: "",
  cdst: "",
  cloning: false,
  srcTab: "drive" as "drive" | "file",
  engine: "surrect" as "surrect" | "photorec",
  drives: [] as { letter: string; kind: string; size: string; health: string; temp: string }[],
  isAdmin: false,
  driveSel: "",
  drivesLoaded: false,
  hexSrc: "",
  hexOff: 0,
  hexSize: 4096,
  hexData: null as null | { b64: string; size: number; truncated: boolean },
  frag: true,
  projMsg: "",
  patch: null as null | { fn: string; off: string; hex: string; msg: string },
};

const app = document.getElementById("app")!;

function nav(label: string, v: View) {
  return `<button class="nav-btn ${state.view === v ? "active" : ""}" data-view="${v}">${label}</button>`;
}

type SavedCase = { image: string; outdir: string; engine: "surrect" | "photorec"; srcTab: "drive" | "file"; savedAt: string };

function loadCases(): Record<string, SavedCase> {
  try {
    return JSON.parse(localStorage.getItem("surrect.cases") || "{}");
  } catch { return {}; }
}

function projCard() {
  const cases = loadCases();
  const names = Object.keys(cases);
  const rows = names.map(n =>
    `<div class="row" style="margin-top:4px"><span style="flex:1">${n} <span class="badge">${cases[n].engine}</span></span><button class="btn" data-case="${n}">Open</button><button class="btn" data-casedel="${n}">Forget</button></div>`).join("");
  return `<div class="card"><strong>Saved cases</strong><p class="sub" style="margin:4px 0 8px">Pick up where you left off — restores your source, engine and file list.</p>
    <div class="row"><input id="casename" class="input" placeholder="case name (e.g. USB stick)" /><button class="btn" id="casesave">Save this case</button></div>
    ${rows || `<p class="sub">No saved cases yet.</p>`}
    <div class="row" style="margin-top:8px"><button class="btn" id="casebackup">Copy backup code</button><button class="btn" id="caserestore">Restore from code</button></div>
    <textarea id="caseio" class="input" style="min-width:100%;height:56px;margin-top:8px" placeholder="backup code appears here — keep it somewhere safe"></textarea>
    ${state.projMsg ? `<p class="sub" style="margin:4px 0 0">${state.projMsg}</p>` : ""}</div>`;
}

async function openCase(name: string) {
  const c = loadCases()[name];
  if (!c) return;
  state.image = c.image; state.outdir = c.outdir; state.engine = c.engine; state.srcTab = c.srcTab;
  state.projMsg = `Opened “${name}” — file list reloaded from disk.`;
  await refreshResults();
  render();
}

function shell(body: string) {
  return `
    <nav class="sidebar">
      <div class="brand">Surrect</div>
      ${nav("Start", "source")}${nav("Recover", "scan")}${nav("My files", "results")}${nav("Deleted", "forensics")}${nav("Report", "audit")}${nav("Copy disk", "image")}${nav("Inspect", "hex")}
    </nav>
    <main class="main">${body}</main>`;
}

function render() {
  let body = "";
  if (state.view === "source") {
    const tabs = `<div class="row" style="margin-bottom:12px">
        <button class="btn ${state.srcTab === "drive" ? "primary" : ""}" data-tab="drive">A real drive</button>
        <button class="btn ${state.srcTab === "file" ? "primary" : ""}" data-tab="file">A disk copy</button>
      </div>`;
    const engineTabs = `<div class="row" style="margin-bottom:12px">
        <button class="btn ${state.engine === "surrect" ? "primary" : ""}" data-engine="surrect">Surrect — fast, keeps file names</button>
        <button class="btn ${state.engine === "photorec" ? "primary" : ""}" data-engine="photorec">PhotoRec — finds more file types</button>
      </div>`;
    if (state.srcTab === "drive") {
      const opts = state.drives.map(d => {
        const gb = d.size ? (Number(d.size) / 1073741824).toFixed(0) + " GB" : "";
        const dot = d.health === "Healthy" ? "🟢" : (d.health === "Warning" ? "🟡" : (d.health === "Unhealthy" ? "🔴" : "⚪"));
        const tmp = d.temp ? ` ${d.temp}°C` : "";
        return `<option value="${d.letter}" ${state.driveSel === d.letter ? "selected" : ""}>${dot} ${d.letter} — ${d.kind} ${gb} (${d.health}${tmp})</option>`;
      }).join("");
      body = `
      <h1>Where are your lost files?</h1><p class="sub">Pick the drive, like Recuva does. ${state.isAdmin ? "Ready — this app can read drives now." : "Tip: live drives need a quick restart as administrator — everything else works as-is."}</p>
      ${state.isAdmin ? "" : `<div class="card" style="border-color:var(--primary);background:var(--info-fill);color:var(--on-info)">💡 <strong>Heads up, no rush:</strong> you're running normally, which is perfectly fine. Only <strong>live drive</strong> reading needs administrator rights — close Surrect, right-click it → <strong>Run as administrator</strong>, and come back whenever. Disk copies work right now, no restart needed.</div>`}
      ${tabs}
      ${engineTabs}
      <div class="card"><div class="row">
        <select id="drive" class="input">${opts || "<option>loading…</option>"}</select>
        <button class="btn primary" id="scandrive" ${!state.driveSel || state.scanning ? "disabled" : ""}>Find my files</button>
      </div></div>
      <div class="card"><p class="sub" style="margin:0 0 8px">Safer: copy the drive first, then recover from the copy — the original stays untouched.</p><div class="row">
        <input id="ddst" class="input" placeholder="C:\\rescue\\drive-e.img" value="${state.cdst}" />
        <button class="btn" id="imgdrive" ${!state.driveSel || state.cloning ? "disabled" : ""}>${state.cloning ? "Copying…" : "Copy first"}</button>
      </div></div>
      ${projCard()}`;
  } else {
      body = `
      <h1>Already have a disk copy?</h1><p class="sub">Use a disk image file — the safest way to recover.</p>
      ${tabs}
      ${engineTabs}
      <div class="card"><div class="row">
        <input id="img" class="input" placeholder="C:\\images\\disk.img" value="${state.image}" />
        <button class="btn" id="browse">Browse…</button>
      </div></div>
      <div class="card"><div class="row">
        <input id="out" class="input" value="${state.outdir}" />
        <button class="btn primary" id="start" ${!state.image || state.scanning ? "disabled" : ""}>Find my files</button>
      </div></div>
      ${projCard()}`;
  }
  } else if (state.view === "hex") {
    const dump = state.hexData ? hexDump(state.hexData.b64, state.hexOff) : "Pick a source and press Show — live drives need admin rights.";
    body = `<h1>Look inside</h1><p class="sub">Expert view: raw disk bytes at any spot. Nothing here changes your disk.</p>
      <div class="card"><div class="row">
        <input id="hsrc" class="input" placeholder="image file or \\\\.\\E:" value="${state.hexSrc || state.image}" />
        <input id="hoff" class="input" style="min-width:140px" placeholder="position (e.g. 4096 or 0x1000)" value="${state.hexOff}" />
        <button class="btn primary" id="hread">Show</button>
        <button class="btn" id="hprev">◀ Prev</button>
        <button class="btn" id="hnext">Next ▶</button>
      </div></div>
      <div class="log">${dump}</div>`;
  } else if (state.view === "scan") {
    const needSource = !state.image
      ? `<div class="card" style="border-color:var(--primary);background:var(--info-fill);color:var(--on-info)">Nothing to recover yet — <strong>pick a drive or a disk copy on the Start page first</strong>, then come back here.<div class="row" style="margin-top:8px"><button class="btn primary" data-view="source">Go to Start</button></div></div>`
      : "";
    body = `
      <h1>Recover</h1><p class="sub">${state.scanning ? "Searching every corner…" : (needSource ? "Waiting for you to pick something." : "Ready when you are.")}</p>
      ${needSource}
      ${state.scanning ? `<div class="progress"><div></div></div>` : ""}
      <div class="card"><div class="row">
        <button class="btn primary" id="start2" ${!state.image || state.scanning ? "disabled" : ""}>Start recovery</button>
        <button class="btn" id="cancel" ${!state.scanning ? "disabled" : ""}>Cancel</button>
        <label style="font:500 13px/16px Inter;color:var(--ink-subtle)"><input type="checkbox" id="frag" ${state.frag ? "checked" : ""} /> piece together broken files (videos, archives)</label>
      </div></div>
      <div class="log">${state.log || "No output yet."}</div>`;
  } else if (state.view === "results") {
    const rows = state.results.map(r =>
      `<tr><td><span class="badge ok">${r.fn.split(".").pop()}</span> ${r.fn}</td><td>${r.off}</td><td>${r.size}</td><td><code>${r.sha ? r.sha.slice(0, 12) : "—"}</code></td><td>${r.chopped ? "Cut short" : "Good"}</td><td><button class="btn" data-prev="${r.fn}">Preview</button> <button class="btn" data-patch="${r.fn}">Patch</button></td></tr>`).join("");
    const pv = state.preview ? previewCard() : "";
    const pc = state.patch ? patchCard() : "";
    body = `<h1>Found files (${state.results.length})</h1><p class="sub">Everything recovered — each with a fingerprint proving it's intact. Patch repairs bytes of a <em>recovered copy</em>; your source is never touched.</p>
      <div class="card"><table class="grid"><thead><tr><th>File</th><th>Found at</th><th>Size</th><th>Fingerprint</th><th>Health</th><th></th></tr></thead><tbody>${rows || `<tr><td colspan="6">Nothing here yet — recover something first.</td></tr>`}</tbody></table></div>${pv}${pc}`;
  } else if (state.view === "forensics") {
    const rows = state.mft.map(m =>
      `<tr><td><span class="badge">${m.fs || "?"}</span></td><td>${m.isDir ? "folder" : "file"}</td><td>${m.name}</td><td>${m.size}</td><td>${m.deleted ? `<span class="badge del">deleted</span>` : ""}</td><td><button class="btn" data-x="${m.off}::${m.name}::${m.fs}">Recover</button></td></tr>`).join("");
    body = `<h1>Deleted files</h1><p class="sub">Recently deleted files with their real names and folders.</p>
      <div class="card"><div class="row"><button class="btn" id="fls" ${!state.image ? "disabled" : ""}>Show deleted files</button></div></div>
      <div class="card"><table class="grid"><thead><tr><th>System</th><th>Kind</th><th>Name &amp; folder</th><th>Size</th><th></th><th></th></tr></thead><tbody>${rows || `<tr><td colspan="6">Nothing yet — show deleted files first.</td></tr>`}</tbody></table></div>`;
  } else if (state.view === "image") {    body = `<h1>Copy a disk safely</h1><p class="sub">Make a complete copy with automatic retries. Recover from the copy — never the original.</p>
      <div class="card"><div class="row">
        <input id="csrc" class="input" placeholder="drive or file to copy from" value="${state.csrc}" />
        <input id="cdst" class="input" placeholder="where to save the copy" value="${state.cdst}" />
      </div></div>
      <div class="card"><div class="row">
        <button class="btn primary" id="clone" ${!state.csrc || !state.cdst || state.cloning ? "disabled" : ""}>${state.cloning ? "Copying…" : "Start copying"}</button>
      </div></div>
      <div class="log">${state.log || "No output yet."}</div>`;
  } else {
    const nDel = state.mft.filter(m => m.deleted).length;
    const repRows = state.results.map(r =>
      `<tr><td>${r.fn}</td><td>${r.size}</td><td><code>${r.sha ? r.sha.slice(0, 16) : "—"}</code></td><td>${r.chopped ? "Cut short" : "Good"}</td></tr>`).join("");
    body = `<h1>Report</h1><p class="sub">The full proof log: every decision the recovery made, line by line.</p>
      <div class="card"><div class="row"><button class="btn primary" id="doprint">Print report (save as PDF)</button></div></div>
      <div class="card" id="printreport"><h2>Surrect recovery report</h2>
      <p>Source: <code>${state.image || "—"}</code><br/>Engine: ${state.engine} &nbsp; Date: ${new Date().toLocaleString()}<br/>
      Files recovered: ${state.results.length} &nbsp; Deleted files listed: ${state.mft.length} (${nDel} deleted)</p>
      <table class="grid"><thead><tr><th>File</th><th>Size</th><th>Fingerprint</th><th>Health</th></tr></thead>
      <tbody>${repRows || `<tr><td colspan="4">No files recovered yet.</td></tr>`}</tbody></table></div>
      <div class="log">${state.audit || "No report yet — recover something first."}</div>`;
  }
  app.innerHTML = shell(body);
  app.querySelectorAll("[data-view]").forEach(b => b.addEventListener("click", () => {
    state.view = (b as HTMLElement).dataset.view as View;
    if (state.view === "source" && state.srcTab === "drive" && !state.drivesLoaded) loadDrives();
    render();
  }));
  app.querySelectorAll("[data-tab]").forEach(b => b.addEventListener("click", () => {
    state.srcTab = (b as HTMLElement).dataset.tab as "drive" | "file";
    if (state.srcTab === "drive" && !state.drivesLoaded) loadDrives();
    render();
  }));
  app.querySelectorAll("[data-engine]").forEach(b => b.addEventListener("click", () => {
    state.engine = (b as HTMLElement).dataset.engine as "surrect" | "photorec";
    render();
  }));
  const img = document.getElementById("img") as HTMLInputElement | null;
  img?.addEventListener("input", () => { state.image = cleanPath(img.value); });
  const out = document.getElementById("out") as HTMLInputElement | null;
  out?.addEventListener("input", () => { state.outdir = cleanPath(out.value) || "recovered"; });
  document.getElementById("browse")?.addEventListener("click", async () => {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const p = await open({ multiple: false });
      if (typeof p === "string") { state.image = p; render(); }
    } catch { appendLog("Couldn't open the file picker — type the path by hand."); }
  });
  const run = () => runCarve();
  document.getElementById("start")?.addEventListener("click", run);
  document.getElementById("start2")?.addEventListener("click", run);
  const frag = document.getElementById("frag") as HTMLInputElement | null;
  frag?.addEventListener("change", () => { state.frag = frag.checked; });
  document.getElementById("cancel")?.addEventListener("click", () => { state.scanning = false; appendLog("cancel requested."); render(); });
  document.getElementById("fls")?.addEventListener("click", () => runFls());
  app.querySelectorAll("[data-x]").forEach(b => b.addEventListener("click", () => {
    const [off, name, fs] = ((b as HTMLElement).dataset.x!).split("::");
    if (fs && !fs.startsWith("NTFS") && fs !== "raw") runFcat(name);
    else runIcat(Number(off));
  }));
  app.querySelectorAll("[data-prev]").forEach(b => b.addEventListener("click", () => runPreview((b as HTMLElement).dataset.prev!)));
  app.querySelectorAll("[data-patch]").forEach(b => b.addEventListener("click", () => {
    state.patch = { fn: (b as HTMLElement).dataset.patch!, off: "0", hex: "", msg: "" };
    render();
  }));
  document.getElementById("papply")?.addEventListener("click", () => runPatch());
  document.getElementById("pcancel")?.addEventListener("click", () => { state.patch = null; render(); });
  const csrc = document.getElementById("csrc") as HTMLInputElement | null;
  csrc?.addEventListener("input", () => { state.csrc = cleanPath(csrc.value); });
  const cdst = document.getElementById("cdst") as HTMLInputElement | null;
  cdst?.addEventListener("input", () => { state.cdst = cleanPath(cdst.value); });
  document.getElementById("clone")?.addEventListener("click", () => runClone());
  document.getElementById("doprint")?.addEventListener("click", () => window.print());
  document.getElementById("casesave")?.addEventListener("click", () => {
    const inp = document.getElementById("casename") as HTMLInputElement | null;
    const name = (inp?.value || "").trim();
    if (!name) { state.projMsg = "Give the case a name first."; render(); return; }
    const cases = loadCases();
    cases[name] = { image: state.image, outdir: state.outdir, engine: state.engine, srcTab: state.srcTab, savedAt: new Date().toISOString() };
    try {
      localStorage.setItem("surrect.cases", JSON.stringify(cases));
      state.projMsg = `Saved “${name}”.`;
    } catch { state.projMsg = "Couldn't save (browser storage full?)."; }
    render();
  });
  app.querySelectorAll("[data-case]").forEach(b => b.addEventListener("click", () => openCase((b as HTMLElement).dataset.case!)));
  app.querySelectorAll("[data-casedel]").forEach(b => b.addEventListener("click", () => {
    const cases = loadCases();
    delete cases[(b as HTMLElement).dataset.casedel!];
    try { localStorage.setItem("surrect.cases", JSON.stringify(cases)); } catch { /* ignore */ }
    render();
  }));
  document.getElementById("casebackup")?.addEventListener("click", () => {
    const ta = document.getElementById("caseio") as HTMLTextAreaElement | null;
    if (ta) { ta.value = JSON.stringify(loadCases()); ta.select(); }
    state.projMsg = "Backup code ready above — copy it somewhere safe.";
    render();
    const ta2 = document.getElementById("caseio") as HTMLTextAreaElement | null;
    if (ta2) ta2.value = JSON.stringify(loadCases());
  });
  document.getElementById("caserestore")?.addEventListener("click", () => {
    const ta = document.getElementById("caseio") as HTMLTextAreaElement | null;
    try {
      const incoming = JSON.parse(ta?.value || "");
      const cases = loadCases();
      for (const k of Object.keys(incoming)) cases[k] = incoming[k];
      localStorage.setItem("surrect.cases", JSON.stringify(cases));
      state.projMsg = "Backup restored.";
    } catch { state.projMsg = "That code doesn't look like a Surrect backup."; }
    render();
  });
  const drive = document.getElementById("drive") as HTMLSelectElement | null;
  drive?.addEventListener("change", () => { state.driveSel = drive.value; });
  const ddst = document.getElementById("ddst") as HTMLInputElement | null;
  ddst?.addEventListener("input", () => { state.cdst = cleanPath(ddst.value); });
  document.getElementById("scandrive")?.addEventListener("click", () => {
    if (!state.driveSel) return;
    state.image = `\\\\.\\${state.driveSel}`;  // keep the colon: \\.\C: is the drive
    runCarve();
  });
  document.getElementById("imgdrive")?.addEventListener("click", async () => {
    if (!state.driveSel || !state.cdst) { appendLog("pick a drive and a destination file first."); render(); return; }
    state.csrc = `\\\\.\\${state.driveSel}`;
    await runClone();
    state.image = state.cdst;  // scan the fresh copy next
    state.srcTab = "file";
    render();
  });
  document.getElementById("hread")?.addEventListener("click", () => runHexRead());
  const stepHex = (d: number) => {
    state.hexOff = Math.max(0, state.hexOff + d);
    const inp = document.getElementById("hoff") as HTMLInputElement | null;
    if (inp) inp.value = String(state.hexOff);
    runHexRead();
  };
  document.getElementById("hprev")?.addEventListener("click", () => stepHex(-state.hexSize));
  document.getElementById("hnext")?.addEventListener("click", () => stepHex(state.hexSize));
}

async function loadDrives() {
  try {
    const r = await invoke<{ admin: boolean; drives: typeof state.drives }>("list_drives");
    state.isAdmin = r.admin;
    state.drives = r.drives;
    if (!state.driveSel && r.drives.length) state.driveSel = r.drives[0].letter;
  } catch (e) { appendLog(String(e)); }
  state.drivesLoaded = true;
  render();
}

function hexDump(b64: string, baseOff: number, rows = 256) {
  const bytes = atob(b64);
  let hex = "";
  for (let i = 0; i < Math.min(bytes.length, rows); i += 16) {
    const row = bytes.slice(i, i + 16);
    const hx = [...row].map(c => c.charCodeAt(0).toString(16).padStart(2, "0")).join(" ");
    const asc = [...row].map(c => { const n = c.charCodeAt(0); return n >= 32 && n < 127 ? c : "."; }).join("");
    hex += (baseOff + i).toString(16).padStart(8, "0") + "  " + hx.padEnd(47) + "  " + asc + "\n";
  }
  return hex;
}

function previewCard() {
  const p = state.preview!;
  const ext = p.fn.split(".").pop()!.toLowerCase();
  const mime: Record<string, string> = { jpg: "image/jpeg", png: "image/png", gif: "image/gif", bmp: "image/bmp", webp: "image/webp", ico: "image/x-icon" };
  let inner: string;
  if (mime[ext] && p.size < 2 * 1024 * 1024) {
    inner = `<img src="data:${mime[ext]};base64,${p.b64}" style="max-width:100%;border:1px solid var(--hairline);border-radius:10px;" />`;
  } else {
    inner = `<div class="log">${hexDump(p.b64, 0)}${p.truncated ? "… (truncated)" : ""}</div>`;
  }
  return `<div class="card"><div class="row"><strong>${p.fn}</strong><span class="badge">${p.size} bytes</span></div><div style="margin-top:8px">${inner}</div></div>`;
}

async function runPatch() {
  const p = state.patch;
  if (!p) return;
  const offEl = document.getElementById("poff") as HTMLInputElement | null;
  const hexEl = document.getElementById("phex") as HTMLInputElement | null;
  const off = Number((offEl?.value ?? p.off).trim());
  const hex = (hexEl?.value ?? p.hex).trim();
  if (!Number.isFinite(off) || off < 0 || !hex) {
    state.patch = { ...p, msg: "Give a position (0 or more) and some hex bytes." };
    render();
    return;
  }
  try {
    const r = await invoke<{ sha: string; size: number }>("write_file", { outdir: state.outdir, file: p.fn, off: Math.floor(off), hexdata: hex });
    state.patch = { ...p, msg: `Patched — new fingerprint ${r.sha.slice(0, 16)}… (${r.size} bytes).` };
    await refreshResults();
    state.preview = null;
  } catch (e) { state.patch = { ...p, msg: String(e) }; }
  render();
}

function patchCard() {
  const p = state.patch!;
  return `<div class="card"><div class="row"><strong>Repair ${p.fn}</strong><span class="badge">copy only — source untouched</span></div>
    <div class="row" style="margin-top:8px">
      <input id="poff" class="input" style="min-width:140px" placeholder="position (e.g. 0)" value="${p.off}" />
      <input id="phex" class="input" style="min-width:280px" placeholder="new bytes as hex (e.g. FF D8)" value="${p.hex}" />
      <button class="btn primary" id="papply">Apply patch</button>
      <button class="btn" id="pcancel">Close</button>
    </div>${p.msg ? `<p class="sub" style="margin:8px 0 0">${p.msg}</p>` : ""}</div>`;
}

async function runPreview(fn: string) {
  try {
    const h = await invoke<{ b64: string; size: number; truncated: boolean }>("read_head", { outdir: state.outdir, file: fn, off: 0, max: 2097152 });
    state.preview = { fn, ...h };
  } catch (e) { appendLog(String(e)); }
  render();
}

function parseOff(s: string): number {
  s = s.trim();
  if (/^0x/i.test(s)) return parseInt(s, 16);
  const n = Number(s);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : NaN;
}

async function runHexRead() {
  const raw = (document.getElementById("hsrc") as HTMLInputElement | null)?.value || state.hexSrc || state.image;
  const src = cleanPath(raw);
  const offraw = (document.getElementById("hoff") as HTMLInputElement | null)?.value ?? String(state.hexOff);
  const off = parseOff(offraw);
  if (!src || !Number.isFinite(off)) { state.hexData = null; render(); return; }
  state.hexSrc = src; state.hexOff = off;
  try {
    state.hexData = await invoke<{ b64: string; size: number; truncated: boolean }>("read_at", { image: src, off, max: state.hexSize });
  } catch (e) { appendLog(String(e)); state.hexData = null; }
  render();
}

async function runClone() {
  if (!state.csrc || !state.cdst) return;
  state.cloning = true; render();
  appendLog(`$ surrect --clone "${state.csrc}" "${state.cdst}"`);
  try {
    const res = await invoke<string>("run_clone", { image: state.csrc, dst: state.cdst, block: 1048576, retries: 3 });
    appendLog(res);
  } catch (e) { appendLog(String(e)); }
  state.cloning = false; render();
}

function appendLog(s: string) { state.log += s + "\n"; }

// Windows users paste paths with quotes ("C:\x") — strip them + whitespace
// at the boundary so the engine always gets a clean path.
function cleanPath(s: string) {
  return s.trim().replace(/^["']+|["']+$/g, "").trim();
}

async function runCarve() {
  if (!state.image) {
    state.view = "scan"; state.scanning = false;
    appendLog("Nothing picked yet — choose a drive or disk copy on the Start page first.");
    render();
    return;
  }
  state.view = "scan"; state.scanning = true; state.log = ""; render();
  if (state.image.startsWith("\\\\.\\") && !state.isAdmin) {
    appendLog("Quick note: live drives open best as administrator — this attempt may come back empty, and that's normal.");
    appendLog("Whenever you're ready: close Surrect, right-click it → Run as administrator, and try again.");
    render();
  }
  if (state.engine === "photorec") {
    appendLog(`$ photorec /d "${state.outdir}" /cmd "${state.image}" partition_none,fileopt,everything,enable,search`);
    render();
    try {
      const r = await invoke<{ log: string; dir: string }>("run_photorec", { image: state.image, outdir: state.outdir });
      appendLog(r.log.split("\n").slice(-12).join("\n"));
      state.outdir = r.dir;  // photorec appends .1, .2...
      await refreshResults();
    } catch (e) {
      appendLog(`photorec failed: ${String(e)}`);
    }
    state.scanning = false; render();
    return;
  }
  appendLog(`$ surrect "${state.image}" -o "${state.outdir}"${state.frag ? " --frag" : ""}`);
  try {
    const res = await invoke<string>("run_carve", { image: state.image, outdir: state.outdir, frag: state.frag });
    appendLog(res);
    await refreshResults();
  } catch (e) {
    appendLog(`Couldn't reach the recovery engine: ${String(e)}\nTip: run 'py ../surrect.py "${state.image}" -o "${state.outdir}"' yourself, then come back.`);
  }
  state.scanning = false; render();
}

async function refreshResults() {
  try {
    const files = await invoke<{ fn: string; off: number; size: number; chopped: boolean; sha: string }[]>("list_results", { outdir: state.outdir });
    state.results = files;
    try {
      state.audit = await invoke<string>("read_audit", { outdir: state.outdir });
    } catch {
      state.audit = "(no report file — PhotoRec run; see the Recover page log + report.xml)";
    }
  } catch { /* web-only dev: leave empty */ }
}

async function runFls() {
  try {
    const recs = await invoke<typeof state.mft>("run_fls", { image: state.image });
    state.mft = recs; render();
  } catch (e) { appendLog(String(e)); render(); }
}

async function runIcat(off: number) {
  try {
    const msg = await invoke<string>("run_icat", { image: state.image, off, outdir: state.outdir });
    appendLog(msg); render();
  } catch (e) { appendLog(String(e)); render(); }
}

async function runFcat(path: string) {
  try {
    const msg = await invoke<string>("run_fcat", { image: state.image, path, outdir: state.outdir });
    appendLog(msg); render();
  } catch (e) { appendLog(String(e)); render(); }
}

render();
loadDrives();
