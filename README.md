# Surrect

**File recovery that proves itself.** A signature carver, filesystem recovery engine, and fragment reassembly tool — CLI and desktop app — with a measured scoreboard instead of marketing claims.

## The 1TB Gauntlet (measured, not claimed)

Surrect was validated against a synthetic 1-terabyte sparse image seeded with 200 known objects — 160 contiguous files across 11 formats (10 planted past the 900GB mark), 20 deliberately fragmented MP4s (box-boundary splits, 1–16MB zero gaps), and 20 decoys that must be rejected. The full harness lives in [`tests/make_gauntlet.py`](tests/make_gauntlet.py) and reproduces from a fixed seed.

| Metric | Result |
|---|---|
| Recall | **179/180 = 99.4%** |
| Precision | **179/180 = 99.4%** (0 decoys carved) |
| Fragmented MP4 reassembly | **20/20**, byte-exact, gaps up to 15MB |
| Files past 900GB | **32/32** (64-bit offsets proven) |
| Scan | 1,099,511,627,776 bytes end-to-end |

The single miss is a documented limitation: one JPEG whose random test payload contained a premature `FF D9` byte pair; footer-first carving stops at the first plausible marker. Real JPEG entropy data escapes those bytes. Receipts: [`score.json`](score.json), [`groundtruth.json`](groundtruth.json).

## What it does

- **Signature carving** — 29 formats with buffer-direct validators (PNG IHDR, BMP DIB, RIFF/MP4 box walks, PE, ELF, TAR checksum, ICO directory, ID3 syncsafe…). Format-aware sizing: exact sizes from SQLite/ICO headers; a 64KB zero-gap stop ends headerless carves instead of ballooning them.
- **Filesystem recovery with names** — NTFS (MFT walk, data runs, folder paths, deleted flags), FAT12/16/32 (LFN, `0xE5` deleted), exFAT (Unicode names, NoFatChain). Extract via `icat`/`rec`/`fcat`.
- **Fragment reassembly** — MP4 box-boundary stitching with backtracking validation and decoy rejection (a valid MP4 has exactly one `ftyp`); ZIP CRC-proven bridging over intruding files with repack.
- **Live drives** — Recuva-style raw drive reads (`\\.\E:`), SMART health badges, hex viewer, and a resume-able ddrescue-style imager whose `.map` skips good blocks and retries bad ones after interruption.
- **Checkpointing** — phase-1 scan results persist to `hits.json`; any interruption (crash, reboot, patch) resumes in seconds.
- **Proof chain** — `manifest.csv` with SHA-256 per file, `audit.txt` decision log, gauntlet `score.json`.

## Desktop app

Tauri 2 shell with two engines: the native Surrect engine, plus **genuine PhotoRec 7.2** as a bundled sidecar (separate GPL binary, mere aggregation — see [`THIRD_PARTY.txt`](surrect-desktop/src-tauri/binaries/THIRD_PARTY.txt)). Live drive picker, scan/preview/hash flow, forensics listing, imaging view, hex viewer.

Build from source (Windows, 64-bit):

```
# engine sidecar (needs Python 3.11+)
py -m PyInstaller --onefile --noconsole --distpath surrect-desktop/src-tauri/binaries ^
    --name surrect-x86_64-pc-windows-msvc surrect.py

# PhotoRec sidecar: download testdisk-7.2.win64.zip from cgsecurity.org,
# copy photorec_win.exe as surrect-desktop/src-tauri/binaries/photorec-x86_64-pc-windows-msvc.exe
# plus its cyg*.dll dependencies and 63/cygwin terminfo (see THIRD_PARTY.txt)

cd surrect-desktop
npm install
npx tauri build   # -> MSI + NSIS installers in src-tauri/target/release/bundle
```

## CLI quick start

```
py surrect.py image.dd -o out --frag          # carve + reassemble
py surrect.py image.dd --fls                  # list files with paths (NTFS/FAT/exFAT)
py surrect.py image.dd --rec 5                # extract NTFS MFT record #5
py surrect.py image.dd --fcat "/docs/a.txt"   # extract FAT/exFAT file by path
py surrect.py --clone \\.\E: rescue.img       # image with retry map (resumable)
py surrect.py --list-drives                   # drives + SMART health
```

## Testing

The regression suite in [`tests/`](tests) locks every bug the gauntlet hunt uncovered — WAV-embedded ICO false positives, the MP4 4-byte prefix loss, the stitcher objective that preferred truncated files, max-size ballooning on wiped space, checkpoint resume parity, decoy rejection, zero-gap stitching:

```
py tests\test_mp4frag.py
py tests\test_carve_parity.py
py tests\test_balloon.py
```

## License

Surrect's own code is MIT licensed — see [LICENSE](LICENSE). The bundled PhotoRec 7.2 binary is GPL v2+ (Christophe GRENIER, cgsecurity.org), shipped unmodified as a separate program with its license and source pointer in `THIRD_PARTY.txt`.

Surrect studied TestDisk/PhotoRec, Scalpel, Foremost, The Sleuth Kit, libfsntfs and NTFS-3G as references; it contains no third-party code.
