//! Surrect Tauri shell — thin bridge to the Python sidecar (surrect v3).
//! Commands mirror the CLI: carve / list_results / read_audit / fls / icat / clone / preview.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::collections::HashMap;
use std::process::Command;

#[derive(Serialize)]
struct CarvedFile {
    fn_: String,
    off: u64,
    size: u64,
    chopped: bool,
    sha: String,
}

#[derive(Serialize)]
struct MftRec {
    off: i64,
    num: i64,
    seq: u16,
    #[serde(rename = "isDir")]
    is_dir: bool,
    name: String,
    deleted: bool,
    fs: String,
    size: u64,
    date: String,
}

#[derive(serde::Deserialize)]
struct FlsRec {
    num: i64,
    off: i64,
    is_dir: bool,
    path: String,
    deleted: bool,
    size: u64,
    #[serde(default)]
    date: String,
}

#[derive(serde::Deserialize)]
struct FlsJson {
    fs: String,
    records: Vec<FlsRec>,
}

#[derive(Serialize)]
struct Head {
    b64: String,
    size: u64,
    truncated: bool,
}

#[derive(Serialize)]
struct Drive {
    letter: String,
    kind: String,
    size: String,
    health: String,
    temp: String,
}

#[derive(Serialize)]
struct Patched {
    sha: String,
    size: u64,
}

#[tauri::command]
fn write_file(outdir: String, file: String, off: u64, hexdata: String) -> Result<Patched, String> {
    // Repair bytes of a RECOVERED file only (never touches sources/images).
    // Must fit inside the existing file; returns the new SHA-256.
    let p = std::path::Path::new(&outdir).join(&file);
    if !p.starts_with(std::path::Path::new(&outdir)) {
        return Err("bad filename".into());
    }
    let hexdata: String = hexdata.chars().filter(|c| !c.is_whitespace()).collect();
    if hexdata.len() % 2 != 0 {
        return Err("hex must have an even number of digits".into());
    }
    let mut raw = Vec::with_capacity(hexdata.len() / 2);
    let h = hexdata.as_bytes();
    let mut i = 0;
    while i < h.len() {
        let b = u8::from_str_radix(std::str::from_utf8(&h[i..i+2]).map_err(|e| e.to_string())?, 16)
            .map_err(|_| "bad hex digit".to_string())?;
        raw.push(b);
        i += 2;
    }
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new().read(true).write(true).open(&p).map_err(|e| e.to_string())?;
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    if off.checked_add(raw.len() as u64).unwrap_or(u64::MAX) > size {
        return Err(format!("patch of {} bytes at {} overruns the {}-byte file", raw.len(), off, size));
    }
    f.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
    f.write_all(&raw).map_err(|e| e.to_string())?;
    drop(f);
    Ok(Patched { sha: sha256_file(&p), size })
}

#[derive(Serialize)]
struct DriveList {
    admin: bool,
    drives: Vec<Drive>,
}

fn triple() -> &'static str {
    "x86_64-pc-windows-msvc"
}

fn resolve_bin(base: &str) -> Option<String> {
    // 1) next to the running app exe (bundled layout, triple may be stripped or kept)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in [format!("{base}.exe"), format!("{base}-{}.exe", triple())] {
                let p = dir.join(&name);
                if p.is_file() {
                    return Some(p.to_string_lossy().to_string());
                }
            }
        }
    }
    // 2) dev layout: src-tauri/binaries/<base>-<triple>.exe
    let dev = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("binaries").join(format!("{base}-{}.exe", triple()));
    if dev.is_file() {
        return Some(dev.to_string_lossy().to_string());
    }
    None
}

fn run_bin(bin: &str, args: &[&str], cwd: Option<&str>, extra_env: &[(&str, &str)]) -> Result<String, String> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().map_err(|e| format!("spawn {bin}: {e}"))?;
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    if out.status.success() { Ok(s) } else { Err(s) }
}

fn run_sidecar(args: &[&str]) -> Result<String, String> {
    // surrect: prefer bundled exe, fall back to dev `py ../surrect.py`
    if let Some(bin) = resolve_bin("surrect") {
        return run_bin(&bin, args, None, &[]);
    }
    let out = Command::new("py").arg("../surrect.py").args(args).output().map_err(|e| e.to_string())?;
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    if out.status.success() { Ok(s) } else { Err(s) }
}

fn sha256_file(path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let mut h = Sha256::new();
    let mut buf = [0u8; 1048576];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(_) => return String::new(),
        }
    }
    hex_of(h.finalize())
}

fn hex_of(d: impl AsRef<[u8]>) -> String {
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

#[tauri::command]
fn run_carve(image: String, outdir: String, frag: bool) -> Result<String, String> {
    if frag {
        run_sidecar(&[&image, "-o", &outdir, "--frag"])
    } else {
        run_sidecar(&[&image, "-o", &outdir])
    }
}

#[tauri::command]
fn list_results(outdir: String) -> Result<Vec<CarvedFile>, String> {
    // manifest.csv is source of truth for sha + status (v3 backend writes it)
    let mut meta: HashMap<String, (String, bool)> = HashMap::new();
    if let Ok(m) = std::fs::read_to_string(format!("{outdir}/manifest.csv")) {
        for line in m.lines().skip(1) {
            let p: Vec<&str> = line.split(',').collect();
            if p.len() >= 5 {
                meta.insert(p[0].to_string(), (p[3].to_string(), p[4].trim() == "CHOPPED"));
            }
        }
    }
    let rd = std::fs::read_dir(&outdir).map_err(|e| e.to_string())?;
    let mut v = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name == "audit.txt" || name == "manifest.csv" || name == "photorec.log" { continue; }
        // surrect: NNNN_OFFSET.ext | photorec: fNNNNNNN.ext / report.xml
        let parts: Vec<&str> = name.split(['_', '.'].as_ref()).collect();
        let off = if parts.len() >= 3 { parts[1].parse::<u64>().unwrap_or(0) } else { 0 };
        let size = e.metadata().map(|m| m.len()).unwrap_or(0);
        let (mut sha, chopped) = meta.get(&name).cloned().unwrap_or_default();
        if sha.is_empty() && size > 0 && size < 2 * 1024 * 1024 * 1024 {
            sha = sha256_file(&e.path());
        }
        v.push(CarvedFile { fn_: name, off, size, chopped, sha });
    }
    v.sort_by_key(|f| f.off);
    Ok(v)
}

#[tauri::command]
fn read_head(outdir: String, file: String, off: u64, max: u64) -> Result<Head, String> {
    let p = std::path::Path::new(&outdir).join(&file);
    if !p.starts_with(std::path::Path::new(&outdir)) {
        return Err("bad filename".into());
    }
    read_range(&p, off, max)
}

#[tauri::command]
fn read_at(image: String, off: u64, max: u64) -> Result<Head, String> {
    // raw bytes at any offset of an image file OR live drive (admin) — read-only
    read_range(std::path::Path::new(&image), off, max)
}

fn read_range(p: &std::path::Path, off: u64, max: u64) -> Result<Head, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(p).map_err(|e| e.to_string())?;
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    f.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
    let cap = (max.min(1024 * 1024)) as usize;
    let mut buf = vec![0u8; cap];
    let mut got = 0;
    while got < cap {
        match f.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) => return Err(e.to_string()),
        }
    }
    buf.truncate(got);
    Ok(Head { b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &buf), size, truncated: off + (got as u64) < size })
}

#[derive(Serialize)]
struct PhotoRecOut {
    log: String,
    dir: String,
}

#[tauri::command]
fn run_photorec(image: String, outdir: String) -> Result<PhotoRecOut, String> {
    // Genuine PhotoRec 7.2 batch mode (CGSecurity docs: /cmd <device> <commands>).
    // Separate GPL binary, run as-is (mere aggregation — see THIRD_PARTY.txt).
    let bin = resolve_bin("photorec").ok_or("photorec sidecar not found")?;
    std::fs::create_dir_all(&outdir).map_err(|e| e.to_string())?;
    // PhotoRec's ncurses needs a terminfo db: embedded at compile time, laid
    // out as <tmp>/63/cygwin on first run (CGSecurity ships exactly this).
    let termdir = std::env::temp_dir().join("surrect-terminfo");
    let term63 = termdir.join("63");
    let _ = std::fs::create_dir_all(&term63);
    let cf = term63.join("cygwin");
    if !cf.is_file() {
        let _ = std::fs::write(&cf, include_bytes!("../terminfo_63/cygwin"));
    }
    let termdir_s = termdir.to_string_lossy().to_string();
    let is_drive = image.starts_with(r"\\.\");
    let mut envs: Vec<(&str, &str)> = vec![
        ("TERMINFO", &termdir_s),
        ("TERM", "cygwin"),
    ];
    if !is_drive {
        // image files need no admin: dodge the UAC prompt (per CGSecurity docs)
        envs.push(("__COMPAT_LAYER", "RunAsInvoker"));
    }
    let cmd = "partition_none,fileopt,everything,enable,search";
    let log = run_bin(&bin, &["/log", "/d", &outdir, "/cmd", &image, cmd], Some(&outdir), &envs)?;
    // PhotoRec appends .1, .2... — pick the newest matching dir
    let base = std::path::Path::new(&outdir).file_name().and_then(|s| s.to_owned().into_string().ok()).unwrap_or_default();
    let parent = std::path::Path::new(&outdir).parent().map(|p| p.to_path_buf()).unwrap_or_else(|| std::path::PathBuf::from("."));
    let mut best = outdir.clone();
    if let Ok(rd) = std::fs::read_dir(&parent) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n == base || (n.starts_with(&base) && n[base.len()..].starts_with('.')) {
                if e.path().is_dir() && n >= std::path::Path::new(&best).file_name().and_then(|s| s.to_owned().into_string().ok()).unwrap_or_default() {
                    best = e.path().to_string_lossy().to_string();
                }
            }
        }
    }
    Ok(PhotoRecOut { log, dir: best })
}

#[derive(Serialize)]
struct E01Out {
    log: String,
    raw: String,
}

#[tauri::command]
fn run_e01_verify(image: String) -> Result<String, String> {
    // Genuine ewfverify (Joachim Metz libewf tools): recomputes MD5/SHA1 over
    // the evidence and compares with stored hashes. Verbatim output = the proof.
    let bin = resolve_bin("ewfverify").ok_or("ewfverify sidecar not found")?;
    run_bin(&bin, &[&image], None, &[])
}

#[tauri::command]
fn run_e01_export(image: String, outdir: String) -> Result<E01Out, String> {
    // Genuine ewfexport to raw: <outdir>/<stem>.raw, then carve-ready.
    let bin = resolve_bin("ewfexport").ok_or("ewfexport sidecar not found")?;
    std::fs::create_dir_all(&outdir).map_err(|e| e.to_string())?;
    let stem = std::path::Path::new(&image)
        .file_stem().and_then(|s| s.to_owned().into_string().ok())
        .unwrap_or_else(|| "exported".to_string());
    let target = std::path::Path::new(&outdir).join(&stem);
    let target_s = target.to_string_lossy().to_string();
    let log = run_bin(&bin, &["-f", "raw", "-t", &target_s, "-S", "0", "-o", "0", "-u", "-q", &image], Some(&outdir), &[])?;
    let raw = target.with_extension("raw").to_string_lossy().to_string();
    Ok(E01Out { log, raw })
}

#[tauri::command]
fn run_raid_detect(members: String) -> Result<String, String> {
    run_sidecar(&["--raid-detect", "--members", &members])
}

#[tauri::command]
fn run_raid_build(level: u32, members: String, order: String, stripe: u64, rotation: String, missing: Option<u32>, outdir: String) -> Result<String, String> {
    let level_s = match level { 0 => "0", 1 => "1", _ => "5" }.to_string();
    let stripe_s = stripe.to_string();
    let missing_s = missing.map(|m| m.to_string()).unwrap_or_default();
    let mut args: Vec<&str> = vec!["--raid", &level_s, "--members", &members,
        "--order", &order, "--stripe", &stripe_s, "--rotation", &rotation, "-o", &outdir];
    if missing.is_some() {
        args.extend(["--missing", &missing_s]);
    }
    run_sidecar(&args)
}

#[tauri::command]
fn run_clone(image: String, dst: String, block: u64, retries: u32) -> Result<String, String> {
    run_sidecar(&[&"--clone".to_string(), &image, &dst,
        &"--block".to_string(), &block.to_string(),
        &"--retries".to_string(), &retries.to_string()])
}

#[tauri::command]
fn list_drives() -> Result<DriveList, String> {
    // sidecar --list-drives prints: admin=True/False then LETTER|type|size lines
    let s = run_sidecar(&["--list-drives"])?;
    let mut admin = false;
    let mut drives = Vec::new();
    for line in s.lines() {
        let t = line.trim();
        if let Some(x) = t.strip_prefix("admin=") {
            admin = x == "True";
        } else if t.contains('|') {
            let p: Vec<&str> = t.split('|').collect();
            if p.len() >= 2 && p[0].len() == 2 {
                drives.push(Drive {
                    letter: p[0].to_string(),
                    kind: p[1].to_string(),
                    size: p.get(2).unwrap_or(&"").to_string(),
                    health: p.get(3).unwrap_or(&"Unknown").to_string(),
                    temp: p.get(4).unwrap_or(&"").to_string(),
                });
            }
        }
    }
    Ok(DriveList { admin, drives })
}

#[tauri::command]
fn read_audit(outdir: String) -> Result<String, String> {
    std::fs::read_to_string(format!("{outdir}/audit.txt")).map_err(|e| e.to_string())
}

#[tauri::command]
fn run_fls(image: String) -> Result<Vec<MftRec>, String> {
    // structured listing: --fls-json prints one JSON line (any FS: NTFS/FAT/exFAT/raw)
    let s = run_sidecar(&[&image, "-o", "recovered", "--fls-json"])?;
    let line = s.lines().find(|l| l.trim_start().starts_with('{')).ok_or("no fls json")?;
    let j: FlsJson = serde_json::from_str(line).map_err(|e| e.to_string())?;
    Ok(j.records.into_iter().map(|r| MftRec {
        off: r.off, num: r.num, seq: 0, is_dir: r.is_dir, name: r.path,
        deleted: r.deleted, fs: j.fs.clone(), size: r.size, date: r.date,
    }).collect())
}

#[tauri::command]
fn run_fcat(image: String, path: String, outdir: String) -> Result<String, String> {
    run_sidecar(&[&image, "-o", &outdir, "--fcat", &path])
}

#[tauri::command]
fn run_icat(image: String, off: u64, outdir: String) -> Result<String, String> {
    run_sidecar(&[&image, "-o", &outdir, "--icat", &off.to_string()])
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![run_carve, list_results, read_audit, run_fls, run_icat, run_fcat, read_head, read_at, write_file, run_clone, list_drives, run_photorec, run_e01_verify, run_e01_export, run_raid_detect, run_raid_build])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
