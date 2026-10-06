# Surrect

**Bring your lost files back — and prove every one.**

Deleted photos. A formatted drive. A memory card that went silent. Surrect finds what's left and hands it back with its original name, its folder, and a fingerprint proving it's intact.

## Install (Windows, 64-bit)

**[Download Surrect from Releases](../../releases)** — pick the setup `.exe`, click through, done. No Python, no building, no tech skills needed.

## What it does for you

- **Finds deleted files with their real names and folders** — not `file0001.jpg`, but `/photos/beach.jpg`, including what's in the Recycle Bin's blind spot.
- **Digs files out of raw disk bytes** — even when Windows says the drive is empty, unformatted, or "needs formatting."
- **Pieces broken files back together** — split videos and archives get reassembled and verified before you ever see them.
- **Recovers straight from the drive, Recuva-style** — or copies the whole drive first and works from the copy, so the original is never touched.
- **Shows its work** — every recovered file carries a SHA-256 fingerprint, and a full report logs each decision. No black boxes.
- **Two engines inside** — Surrect's own (fast, remembers names) plus the famous PhotoRec (finds 480+ file types). Pick per job.

## Proven, not promised

Surrect was tested against a 1-terabyte image seeded with 200 known objects — everyday files, deliberately fragmented videos, and 20 fakes designed to fool it:

| What was measured | Result |
|---|---|
| Files found | **179/180 (99.4%)** |
| False alarms | **1** (a known edge case, documented) |
| Broken videos reassembled | **20/20, byte-perfect** |
| Files past the 900GB mark | **32/32** |

Details: [`score.json`](score.json). The one miss is an honest, documented limitation (a JPEG whose test data contained a premature end-marker).

## Screens

**Start** (pick a drive or disk copy) → **Recover** (watch it work) → **My files** (preview + fingerprints) → **Deleted** (recently deleted, one-click recover) → **Report** (the proof log) → **Copy disk** (safe full copy with retries) → **Inspect** (expert byte view, read-only).

## Prefer typing?

```
surrect.exe C: -o out --frag        # recover a drive, reassemble broken files
surrect.exe image.dd --fls          # list deleted files with real paths
surrect.exe image.dd --rec 5        # pull out one file by its record number
surrect.exe image.dd --fcat "/docs/a.txt"  # pull out a FAT/exFAT file by path
surrect.exe --clone \\.\E: rescue.img      # copy a sick drive first (resumable)
surrect.exe --list-drives           # drives + health check
```

## Build it yourself

You don't need to — grab the installer above. But everything is reproducible from source:

```
# 1. The recovery engine becomes a single file (needs Python 3.11+)
py -m PyInstaller --onefile --noconsole --distpath surrect-desktop\src-tauri\binaries ^
    --name surrect-x86_64-pc-windows-msvc surrect.py

# 2. The PhotoRec sidecar: download testdisk-7.2.win64.zip from cgsecurity.org,
#    copy photorec_win.exe + its dlls + 63/cygwin terminfo into src-tauri\binaries
#    (provenance documented in THIRD_PARTY.txt)

cd surrect-desktop && npm install && npx tauri build
# -> MSI + setup exe in src-tauri\target\release\bundle
```

Run the permanent regression suite (every bug the 1TB test ever found is locked behind one):

```
py tests\test_mp4frag.py
py tests\test_carve_parity.py
py tests\test_balloon.py
py tests\test_badpaths.py
```

Reproduce the 1TB gauntlet yourself: `py tests\make_gauntlet.py`, scan it, `py tests\score_gauntlet.py`.

## License

Surrect's own code is MIT — see [LICENSE](LICENSE). The app can bundle PhotoRec 7.2 (GPL v2+, Christophe GRENIER) as a separate program; see `THIRD_PARTY.txt` for attribution. Surrect learned from TestDisk/PhotoRec, Scalpel, Foremost, The Sleuth Kit, libfsntfs and NTFS-3G as references; it contains no third-party code.
