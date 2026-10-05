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
  engine: "pycarve" as "pycarve" | "photorec",
  drives: [] as { letter: string; kind: string; size: string; health: string; temp: string }[],
  isAdmin: false,
  driveSel: "",
  drivesLoaded: false,
  hexSrc: "",
  hexOff: 0,
  hexSize: 4096,
  hexData: null as null | { b64: string; size: number; truncated: boolean },
  frag: true,
};

const app = document.getElementById("app")!;

function nav(label: string, v: View) {
  return `<button class="nav-btn ${state.view === v ? "active" : ""}" data-view="${v}">${label}</button>`;
}

function shell(body: string) {
  return `
    <nav class="sidebar">
      <div class="brand">PyCarve</div>
      ${nav("Source", "source")}${nav("Scan", "scan")}${nav("Results", "results")}${nav("Forensics", "forensics")}${nav("Audit", "audit")}${nav("Image", "image")}${nav("Hex", "hex")}
    </nav>
    <main class="main">${body}</main>`;
}

function render() {
  let body = "";
  if (state.view === "source") {
    const tabs = `<div class="row" style="margin-bottom:12px">
        <button class="btn ${state.srcTab === "drive" ? "primary" : ""}" data-tab="drive">Drive (live)</button>
        <button class="btn ${state.srcTab === "file" ? "primary" : ""}" data-tab="file">Image file</button>
      </div>`;
    const engineTabs = `<div class="row" style="margin-bottom:12px">
        <button class="btn ${state.engine === "pycarve" ? "primary" : ""}" data-engine="pycarve">PyCarve (fast, named files)</button>
        <button class="btn ${state.engine === "photorec" ? "primary" : ""}" data-engine="photorec">PhotoRec 7.2 (480 formats)</button>
      </div>`;
    if (state.srcTab === "drive") {
      const opts = state.drives.map(d => {
        const gb = d.size ? (Number(d.size) / 1073741824).toFixed(0) + " GB" : "";
        const dot = d.health === "Healthy" ? "🟢" : (d.health === "Warning" ? "🟡" : (d.health === "Unhealthy" ? "🔴" : "⚪"));
        const tmp = d.temp ? ` ${d.temp}°C` : "";
        return `<option value="${d.letter}" ${state.driveSel === d.letter ? "selected" : ""}>${dot} ${d.letter} — ${d.kind} ${gb} (${d.health}${tmp})</option>`;
      }).join("");
      body = `
      <h1>Source drive</h1><p class="sub">Recuva-style: pick a live drive. ${state.isAdmin ? "Running as admin — raw read ready." : "Needs <strong>Run as administrator</strong> to read drives."}</p>
      ${tabs}
      ${engineTabs}
      <div class="card"><div class="row">
        <select id="drive" class="input">${opts || "<option>loading…</option>"}</select>
        <button class="btn primary" id="scandrive" ${!state.driveSel || state.scanning ? "disabled" : ""}>Scan drive</button>
      </div></div>
      <div class="card"><p class="sub" style="margin:0 0 8px">Safer: image the drive first, then scan the copy.</p><div class="row">
        <input id="ddst" class="input" placeholder="C:\\rescue\\drive-e.img" value="${state.cdst}" />
        <button class="btn" id="imgdrive" ${!state.driveSel || state.cloning ? "disabled" : ""}>${state.cloning ? "Imaging…" : "Image first"}</button>
      </div></div>`;
  } else {
      body = `
      <h1>Source image</h1><p class="sub">Pick a disk image file. Backend: pycarve streaming engine.</p>
      ${tabs}
      ${engineTabs}
      <div class="card"><div class="row">
        <input id="img" class="input" placeholder="C:\\images\\disk.img" value="${state.image}" />
        <button class="btn" id="browse">Browse…</button>
      </div></div>
      <div class="card"><div class="row">
        <input id="out" class="input" value="${state.outdir}" />
        <button class="btn primary" id="start" ${!state.image || state.scanning ? "disabled" : ""}>Start scan</button>
      </div></div>`;
  }
  } else if (state.view === "hex") {
    const dump = state.hexData ? hexDump(state.hexData.b64, state.hexOff) : "Pick a source and press Read — live drives need admin.";
    body = `<h1>Hex viewer</h1><p class="sub">Read-only bytes at any offset. File or live drive.</p>
      <div class="card"><div class="row">
        <input id="hsrc" class="input" placeholder="image file or \\\\.\\E:" value="${state.hexSrc || state.image}" />
        <input id="hoff" class="input" style="min-width:140px" placeholder="offset (0x… or decimal)" value="${state.hexOff}" />
        <button class="btn primary" id="hread">Read</button>
        <button class="btn" id="hprev">◀ Prev</button>
        <button class="btn" id="hnext">Next ▶</button>
      </div></div>
      <div class="log">${dump}</div>`;
  } else if (state.view === "scan") {
    body = `
      <h1>Scan</h1><p class="sub">${state.scanning ? "Carving…" : "Idle"}</p>
      ${state.scanning ? `<div class="progress"><div></div></div>` : ""}
      <div class="card"><div class="row">
        <button class="btn primary" id="start2" ${!state.image || state.scanning ? "disabled" : ""}>Run carve</button>
        <button class="btn" id="cancel" ${!state.scanning ? "disabled" : ""}>Cancel</button>
        <label style="font:500 13px/16px Inter;color:var(--ink-subtle)"><input type="checkbox" id="frag" ${state.frag ? "checked" : ""} /> fragment reassembly (mp4/zip)</label>
      </div></div>
      <div class="log">${state.log || "No output yet."}</div>`;
  } else if (state.view === "results") {
    const rows = state.results.map(r =>
      `<tr><td><span class="badge ok">${r.fn.split(".").pop()}</span> ${r.fn}</td><td>${r.off}</td><td>${r.size}</td><td><code>${r.sha ? r.sha.slice(0, 12) : "—"}</code></td><td>${r.chopped ? "CHOPPED" : "ok"}</td><td><button class="btn" data-prev="${r.fn}">Preview</button></td></tr>`).join("");
    const pv = state.preview ? previewCard() : "";
    body = `<h1>Results (${state.results.length})</h1><p class="sub">Offset-ordered carve IDs + SHA-256 — PhotoRec convention.</p>
      <div class="card"><table class="grid"><thead><tr><th>File</th><th>Offset</th><th>Size</th><th>SHA-256</th><th>Status</th><th></th></tr></thead><tbody>${rows || `<tr><td colspan="6">No results yet — run a scan.</td></tr>`}</tbody></table></div>${pv}`;
  } else if (state.view === "forensics") {
    const rows = state.mft.map(m =>
      `<tr><td><span class="badge">${m.fs || "?"}</span></td><td>${m.isDir ? "dir" : "file"}</td><td>${m.name}</td><td>${m.size}</td><td>${m.deleted ? `<span class="badge del">* deleted</span>` : ""}</td><td><button class="btn" data-x="${m.off}::${m.name}::${m.fs}">extract</button></td></tr>`).join("");
    body = `<h1>Forensics</h1><p class="sub">File listing with paths — NTFS, FAT12/16/32, exFAT. Deleted welcome.</p>
      <div class="card"><div class="row"><button class="btn" id="fls" ${!state.image ? "disabled" : ""}>Run fls</button></div></div>
      <div class="card"><table class="grid"><thead><tr><th>FS</th><th>Type</th><th>Path</th><th>Size</th><th></th><th></th></tr></thead><tbody>${rows || `<tr><td colspan="6">No records yet.</td></tr>`}</tbody></table></div>`;
  } else if (state.view === "image") {    body = `<h1>Disk image</h1><p class="sub">ddrescue-style copy with retry map (.map sidecar).</p>
      <div class="card"><div class="row">
        <input id="csrc" class="input" placeholder="source disk / image" value="${state.csrc}" />
        <input id="cdst" class="input" placeholder="destination image" value="${state.cdst}" />
      </div></div>
      <div class="card"><div class="row">
        <button class="btn primary" id="clone" ${!state.csrc || !state.cdst || state.cloning ? "disabled" : ""}>${state.cloning ? "Imaging…" : "Start image"}</button>
      </div></div>
      <div class="log">${state.log || "No output yet."}</div>`;
  } else {
    body = `<h1>Audit</h1><p class="sub">EOCD / BMP rejection reasons + carve decisions.</p>
      <div class="log">${state.audit || "No audit yet."}</div>`;
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
    state.engine = (b as HTMLElement).dataset.engine as "pycarve" | "photorec";
    render();
  }));
  const img = document.getElementById("img") as HTMLInputElement | null;
  img?.addEventListener("input", () => { state.image = img.value; });
  const out = document.getElementById("out") as HTMLInputElement | null;
  out?.addEventListener("input", () => { state.outdir = out.value; });
  document.getElementById("browse")?.addEventListener("click", async () => {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const p = await open({ multiple: false });
      if (typeof p === "string") { state.image = p; render(); }
    } catch { appendLog("dialog plugin missing — type path manually."); }
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
  const csrc = document.getElementById("csrc") as HTMLInputElement | null;
  csrc?.addEventListener("input", () => { state.csrc = csrc.value; });
  const cdst = document.getElementById("cdst") as HTMLInputElement | null;
  cdst?.addEventListener("input", () => { state.cdst = cdst.value; });
  document.getElementById("clone")?.addEventListener("click", () => runClone());
  const drive = document.getElementById("drive") as HTMLSelectElement | null;
  drive?.addEventListener("change", () => { state.driveSel = drive.value; });
  const ddst = document.getElementById("ddst") as HTMLInputElement | null;
  ddst?.addEventListener("input", () => { state.cdst = ddst.value; });
  document.getElementById("scandrive")?.addEventListener("click", () => {
    if (!state.driveSel) return;
    state.image = `\\\\.\\${state.driveSel.replace(":", "")}`;
    runCarve();
  });
  document.getElementById("imgdrive")?.addEventListener("click", async () => {
    if (!state.driveSel || !state.cdst) { appendLog("pick a drive and a destination file first."); render(); return; }
    state.csrc = `\\\\.\\${state.driveSel.replace(":", "")}`;
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
  const src = (document.getElementById("hsrc") as HTMLInputElement | null)?.value || state.hexSrc || state.image;
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
  appendLog(`$ pycarve --clone "${state.csrc}" "${state.cdst}"`);
  try {
    const res = await invoke<string>("run_clone", { image: state.csrc, dst: state.cdst, block: 1048576, retries: 3 });
    appendLog(res);
  } catch (e) { appendLog(String(e)); }
  state.cloning = false; render();
}

function appendLog(s: string) { state.log += s + "\n"; }

async function runCarve() {
  if (!state.image) return;
  state.view = "scan"; state.scanning = true; state.log = ""; render();
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
  appendLog(`$ pycarve "${state.image}" -o "${state.outdir}"${state.frag ? " --frag" : ""}`);
  try {
    const res = await invoke<string>("run_carve", { image: state.image, outdir: state.outdir, frag: state.frag });
    appendLog(res);
    await refreshResults();
  } catch (e) {
    appendLog(`sidecar fallback: ${String(e)}\nTip: run 'py ../pycarve.py \"${state.image}\" -o \"${state.outdir}\"' manually, then reload.`);
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
      state.audit = "(no audit.txt — PhotoRec run; see Scan log + report.xml)";
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
