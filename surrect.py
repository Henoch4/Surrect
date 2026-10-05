#!/usr/bin/env python3
"""surrect v4 - streaming two-pass carver + NTFS folder recovery + imager + live drives.
v4 changes: single streaming engine for files AND live drives (\\\\.\\E:).
  Pass 1 scans 4MB chunks for validated headers; pass 2 seeks to each header
  and pairs footers with bounded forward reads. O(1) RAM on any size.
Sources: testdisk/src/file_*.c, scalpel.conf, foremost/state.c,
  ntfs-3g/layout.h, sleuthkit/tsk/fs/ntfs.c
"""
import os, sys, argparse, struct, hashlib

MiB = 1024 * 1024
CHUNK = 16 * MiB
OVERLAP = 4096
# ext, header, footer, max, mode   mode: forward|reverse|next|box|riff:XXXX|bmp
SIGS = [
    ("jpg",  b"\xff\xd8\xff", b"\xff\xd9", 50*MiB, "forward"),
    ("png",  bytes.fromhex("89504e470d0a1a0a"), bytes.fromhex("0000000049454e44ae426082"), 20*MiB, "forward"),
    ("pdf",  b"%PDF", b"%EOF", 5*MiB, "reverse"),
    ("gif",  b"GIF89a", b"\x00\x3b", 5*MiB, "forward"),
    ("gif",  b"GIF87a", b"\x00\x3b", 5*MiB, "forward"),
    ("zip",  b"PK\x03\x04", b"PK\x05\x06", 512*MiB, "forward"),
    ("tiff", b"II*\x00", None, 32*MiB, "next"),
    ("tiff", b"MM\x00*", None, 32*MiB, "next"),
    ("wav",  b"RIFF", None, 512*MiB, "riff:WAVE"),
    ("avi",  b"RIFF", None, 2*1024*MiB, "riff:AVI "),
    ("webp", b"RIFF", None, 64*MiB, "riff:WEBP"),
    ("ico",  b"\x00\x00\x01\x00", None, 16*MiB, "next"),
    ("psd",  b"8BPS", None, 256*MiB, "next"),
    ("sqlite", b"SQLite format 3\x00", None, 1*1024*MiB, "next"),
    ("rar",  b"Rar!\x1a\x07", None, 1*1024*MiB, "next"),
    ("7z",   b"7z\xbc\xaf\x27\x1c", None, 1*1024*MiB, "next"),
    ("gz",   b"\x1f\x8b", None, 512*MiB, "next"),
    ("tar",  b"ustar", None, 512*MiB, "next"),
    ("mp3",  b"ID3", None, 64*MiB, "next"),
    ("flac", b"fLaC", None, 256*MiB, "next"),
    ("ogg",  b"OggS", None, 512*MiB, "next"),
    ("mkv",  bytes.fromhex("1A45DFA3"), None, 4*1024*MiB, "next"),
    ("mp4",  b"ftyp", None, 4*1024*MiB, "box"),  # ftyp covers mp4/mov
    ("exe",  b"MZ", None, 256*MiB, "next"),
    ("elf",  b"\x7fELF", None, 256*MiB, "next"),
    ("ole",  bytes.fromhex("D0CF11E0A1B11AE1"), None, 512*MiB, "next"),
    ("rtf",  b"{\\rtf", b"}", 16*MiB, "forward"),
    ("bmp",  b"BM", None, 64*MiB, "bmp"),
]

OBIN = getattr(os, "O_BINARY", 0)

def _valid_buf(buf, i, ext, mx):
    """Buffer-direct validator (no syscalls). buf[i] is the header start.
    Returns True/False, or None when the verdict needs bytes outside buf."""
    try:
        if ext == "png":
            b = buf[i:i+28]
            if len(b) < 28 or b[12:16] != b"IHDR":
                return False
            w, h = struct.unpack_from(">II", b, 16)
            if not (1 <= w <= 10000 and 1 <= h <= 10000):
                return False
            if b[24] not in (1, 2, 4, 8, 16) or b[25] not in (0, 2, 3, 4, 6):
                return False
        elif ext == "bmp":
            b = buf[i:i+54]
            if len(b) < 54:
                return False
            fsize, _, _, pixoff = struct.unpack_from("<IHHI", b, 2)
            if fsize < 54 or fsize > mx or pixoff < 26 or pixoff > fsize:
                return False
            dib = struct.unpack_from("<I", b, 14)[0]
            if dib < 12 or dib > 124:
                return False
            if dib >= 40:
                w, h = struct.unpack_from("<ii", b, 18)
                planes, bpp = struct.unpack_from("<HH", b, 26)
                comp = struct.unpack_from("<I", b, 30)[0]
                if abs(w) < 1 or abs(w) > 10000 or h == 0 or abs(h) > 10000:
                    return False
                if planes != 1 or bpp not in (1, 4, 8, 16, 24, 32) or comp > 3:
                    return False
        elif ext == "ico":
            b = buf[i:i+22]
            if len(b) < 22:
                return False
            rsv, typ, cnt = struct.unpack_from("<HHH", b)
            if rsv != 0 or typ not in (1, 2) or not (1 <= cnt <= 255):
                return False
            # first ICONDIRENTRY must point at real embedded image data.
            # Kills WAV-fmt FPs where 00 00 01 00 sits at +18 (cnt=channels).
            _, _, _, _, planes, bpp, imglen, imgoff = struct.unpack_from("<BBBBHHII", b, 6)
            if imgoff < 22 or imgoff > mx:
                return False
            if i + imgoff + 4 > len(buf):
                return None  # embedded bytes beyond chunk: edge fallback
            emb = buf[i+imgoff:i+imgoff+4]
            if emb[:4] == bytes.fromhex("89504e47") or emb[:2] == b"BM":
                pass  # embedded PNG/BMP: fine
            else:
                dib = struct.unpack_from("<I", buf, i + imgoff)[0]
                if dib < 12 or dib > 124:
                    return False
        elif ext == "tar":
            if i - 257 < 0:
                return None  # need bytes before buf: edge fallback
            blk = buf[i-257:i-257+512]
            if len(blk) < 512 or blk[257:262] != b"ustar":
                return False
            try:
                stored = int(blk[148:156].split(b"\x00")[0].strip() or b"0", 8)
            except ValueError:
                return False
            if sum(blk[:148]) + 256 + sum(blk[156:512]) != stored:
                return False
        elif ext == "exe":
            b = buf[i:i+64]
            if len(b) < 64:
                return False
            e = struct.unpack_from("<I", b, 0x3C)[0]
            if e < 64 or e > mx:
                return False
            return None if i + e + 4 > len(buf) else buf[i+e:i+e+4] == b"PE\x00\x00"
        elif ext == "elf":
            b = buf[i:i+52]
            if len(b) < 52:
                return False
            if not (b[4] in (1, 2) and b[5] in (1, 2) and b[6] == 1):
                return False
        elif ext == "gz":
            b = buf[i:i+10]
            if len(b) < 10 or b[2] != 8 or b[3] & 0xE0:
                return False
        elif ext == "mp3":
            b = buf[i:i+10]
            if len(b) < 10 or b[3] > 4 or b[4] & 0xF0:
                return False
            # syncsafe tag size (bytes 6-9, 7-bit each) must be sane;
            # random data passing this is ~1/2^28
            sz = ((b[6] & 0x7F) << 21) | ((b[7] & 0x7F) << 14) | ((b[8] & 0x7F) << 7) | (b[9] & 0x7F)
            if sz > 256 * 1024 * 1024:
                return False
    except (struct.error, IndexError):
        return False
    return True

def _scan_buf(buf, base, cpos, sigs):
    """Find + buffer-validate headers in buf (base = absolute offset of buf[0]).
    Emits hits with off >= cpos (overlap tail belongs to the previous chunk);
    near-edge candidates are returned for readat fallback."""
    hits, dropped, edge = [], 0, []
    for idx, (ext, hdr, ftr, mx, mode) in enumerate(sigs):
        s = 0
        while True:
            i = buf.find(hdr, s)
            if i == -1:
                break
            off = base + i
            if off < cpos:
                s = i + 1
                continue
            if i - 300 >= 0 and i + 600 <= len(buf):
                v = _valid_buf(buf, i, ext, mx)
                if v is None:
                    edge.append((off, idx))
                elif v:
                    hits.append((off, idx))
                else:
                    dropped += 1
            else:
                edge.append((off, idx))
            s = i + 1
    return hits, dropped, edge

def _scan_range(path, a, b, cpos, sigs):
    """Thread worker: private fd, scan absolute range [a, b)."""
    fd = os.open(path, os.O_RDONLY | OBIN)
    try:
        os.lseek(fd, a, os.SEEK_SET)
        buf = b""
        while len(buf) < b - a:
            c = os.read(fd, (b - a) - len(buf))
            if not c:
                break
            buf += c
    finally:
        os.close(fd)
    return _scan_buf(buf, a, cpos, sigs)

def sha256_of(b):
    return hashlib.sha256(b).hexdigest()

# ---------- random-access reader over files or live drives ----------
class ImgReader:
    def __init__(self, path):
        self.path = path
        self.fd = os.open(path, os.O_RDONLY | OBIN)
        try:
            self.total = os.path.getsize(path)
            self.is_drive = False
        except OSError:
            self.total = None  # live drive: unknown size, read till EOF
            self.is_drive = True

    def close(self):
        os.close(self.fd)

    def readat(self, off, n):
        if off < 0 or n <= 0:
            return b""
        out = bytearray()
        while len(out) < n:
            try:
                os.lseek(self.fd, off + len(out), os.SEEK_SET)
                c = os.read(self.fd, n - len(out))
            except OSError:
                break
            if not c:
                break
            out += c
        return bytes(out)

    def scan_headers(self, sigs, workers=0):
        """Pass 1: header scan. Known-size images use worker PROCESSES (private
        fds, GIL-free C scans, deterministic merged output); live drives and
        small files scan sequentially in-process."""
        if self.total is None:
            return self._scan_stream(sigs)
        workers = workers or max(1, min(8, (os.cpu_count() or 4)))
        if workers <= 1 or self.total < 64 * MiB:
            return self._scan_stream(sigs)
        import concurrent.futures
        ranges = []
        pos = 0
        while pos < self.total:
            end = min(pos + CHUNK, self.total)
            ranges.append((max(0, pos - OVERLAP) if pos else 0, end, pos))
            pos = end
        hits, dropped = [], 0
        path = self.path
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(_scan_range, path, a, b, pos, sigs) for (a, b, pos) in ranges]
            for f in futs:
                h, d, edge = f.result()
                hits += h
                dropped += d
                for off, idx in edge:  # chunk-edge candidates: validate via readat
                    if self._valid(sigs[idx][0], off, sigs[idx][3]):
                        hits.append((off, idx))
                    else:
                        dropped += 1
        hits = sorted(set(hits))
        return hits, dropped, self.total

    def _scan_stream(self, sigs):
        """Pass 1 sequential (files too small to thread, or live drives)."""
        hits, dropped = [], 0
        pos, pending = 0, b""
        while True:
            try:
                os.lseek(self.fd, pos, os.SEEK_SET)
                chunk = os.read(self.fd, CHUNK)
            except OSError:
                break
            if not chunk:
                break
            buf = pending + chunk
            base = pos - len(pending)
            h, d, edge = _scan_buf(buf, base, pos, sigs)
            hits += h
            dropped += d
            for off, idx in edge:
                if self._valid(sigs[idx][0], off, sigs[idx][3]):
                    hits.append((off, idx))
                else:
                    dropped += 1
            pos += len(chunk)
            pending = buf[-OVERLAP:] if len(buf) > OVERLAP else buf
            if not chunk:
                break
        hits = sorted(set(hits))
        return hits, dropped, pos

    def _valid_buf(self, buf, i, ext, mx):
        return _valid_buf(buf, i, ext, mx)

    def _valid(self, ext, off, mx):
        total = self.total if self.total is not None else (1 << 63)
        try:
            if ext == "png":
                b = self.readat(off, 28)
                if len(b) < 28 or b[12:16] != b"IHDR":
                    return False
                w, h = struct.unpack_from(">II", b, 16)
                if not (1 <= w <= 10000 and 1 <= h <= 10000):
                    return False
                if b[24] not in (1, 2, 4, 8, 16) or b[25] not in (0, 2, 3, 4, 6):
                    return False
            elif ext == "bmp":
                b = self.readat(off, 54)
                if len(b) < 54:
                    return False
                fsize, _, _, pixoff = struct.unpack_from("<IHHI", b, 2)
                if fsize < 54 or fsize > mx or pixoff < 26 or pixoff > fsize:
                    return False
                dib = struct.unpack_from("<I", b, 14)[0]
                if dib < 12 or dib > 124:
                    return False
                if dib >= 40:
                    w, h = struct.unpack_from("<ii", b, 18)
                    planes, bpp = struct.unpack_from("<HH", b, 26)
                    comp = struct.unpack_from("<I", b, 30)[0]
                    if abs(w) < 1 or abs(w) > 10000 or h == 0 or abs(h) > 10000:
                        return False
                    if planes != 1 or bpp not in (1, 4, 8, 16, 24, 32) or comp > 3:
                        return False
            elif ext == "ico":
                b = self.readat(off, 22)
                if len(b) < 22:
                    return False
                rsv, typ, cnt = struct.unpack_from("<HHH", b)
                if rsv != 0 or typ not in (1, 2) or not (1 <= cnt <= 255):
                    return False
                _, _, _, _, planes, bpp, imglen, imgoff = struct.unpack_from("<BBBBHHII", b, 6)
                if imgoff < 22 or imgoff > mx:
                    return False
                emb = self.readat(off + imgoff, 4)
                if len(emb) < 4:
                    return False
                if emb[:4] == bytes.fromhex("89504e47") or emb[:2] == b"BM":
                    pass
                else:
                    dib = struct.unpack_from("<I", emb)[0]
                    if dib < 12 or dib > 124:
                        return False
            elif ext == "tar":
                blk = off - 257
                if blk < 0:
                    return False
                b = self.readat(blk, 512)
                if len(b) < 512 or b[257:262] != b"ustar":
                    return False
                try:
                    stored = int(b[148:156].split(b"\x00")[0].strip() or b"0", 8)
                except ValueError:
                    return False
                if sum(b[:148]) + 256 + sum(b[156:512]) != stored:
                    return False
            elif ext == "exe":
                b = self.readat(off, 64)
                if len(b) < 64:
                    return False
                e = struct.unpack_from("<I", b, 0x3C)[0]
                if e < 64 or e > mx:
                    return False
                if self.readat(off+e, 4) != b"PE\x00\x00":
                    return False
            elif ext == "elf":
                b = self.readat(off, 52)
                if len(b) < 52 or b[4] not in (1, 2) or b[5] not in (1, 2) or b[6] != 1:
                    return False
            elif ext == "gz":
                b = self.readat(off, 10)
                if len(b) < 10 or b[2] != 8 or b[3] & 0xE0:
                    return False
            elif ext == "mp3":
                b = self.readat(off, 5)
                if len(b) < 5 or b[3] > 4 or b[4] & 0xF0:
                    return False
        except (struct.error, IndexError):
            return False
        return True

    def find_footers(self, hdr_off, start, needle, maxlen, min_len=64, cap=4096):
        """Bounded forward footer search. Returns [end_off...] (after footer)."""
        out = []
        rng = maxlen if self.total is None else min(maxlen, max(0, self.total - start))
        scanned = 0
        carry = b""
        while scanned < rng and len(out) < cap:
            want = min(CHUNK, rng - scanned)
            c = self.readat(start + scanned, want)
            if not c:
                break
            buf = carry + c
            s = 0
            while len(out) < cap:
                i = buf.find(needle, s)
                if i == -1:
                    break
                abs_off = start + scanned - len(carry) + i
                if abs_off >= start and abs_off + len(needle) - hdr_off >= min_len:
                    out.append(abs_off + len(needle))
                s = i + 1
            scanned += len(c)
            carry = buf[-(len(needle)-1):] if len(needle) > 1 else b""
        return out

    def box_walk(self, ftyp_off, mx, next_hdr):
        """MP4/MOV box walk from ftyp header. Every box must be type-plausible
        AND chained (or a known tail near EOF) — random bytes can't walk far."""
        start = ftyp_off - 4
        if start < 0:
            return None
        hard = start + mx if self.total is None else min(start + mx, self.total)
        b = self.readat(start, 8)
        if len(b) < 8 or b[4:8] != b"ftyp":
            return None
        size0 = struct.unpack_from(">I", b)[0]
        if size0 < 8:
            return None
        if next_hdr <= start:
            next_hdr = hard
        end_limit = min(next_hdr, hard)
        eof_slack = (self.total or hard) - (1 << 20)
        pos = start
        while pos + 8 <= end_limit:
            h = box_at(self, pos, self.total)
            if not h:
                break
            sz, typ = h
            if sz == 0:
                return hard
            nxt = pos + sz
            if nxt > end_limit:
                if typ in MP4_KNOWN and nxt <= hard and nxt >= eof_slack:
                    return nxt
                break
            if box_at(self, nxt, self.total):
                pos = nxt
                continue
            if typ in MP4_KNOWN and nxt >= eof_slack:
                return nxt
            break
        return pos if pos - start >= size0 else None

    def riff_size(self, off, kind, mx):
        b = self.readat(off, 12)
        if len(b) < 12 or b[8:12] != kind.encode("latin1"):
            return None
        size = struct.unpack_from("<I", b, 4)[0]
        end = off + 8 + size + (size & 1)
        if end - off < 12 or end - off > mx:
            return None
        if self.total is not None and end > self.total:
            return None
        return end

    def zero_gap(self, start, limit, run=64 * 1024):
        """First offset of an all-zero run >= `run` bytes within [start, limit), or None.
        Sparse/wiped regions terminate headerless carves here instead of ballooning
        to max size (gauntlet-proven: sqlite/1GB, mp3/64MB balloons killed the disk)."""
        pos, zrun, zstart = start, 0, start
        while pos < limit:
            c = self.readat(pos, min(CHUNK, limit - pos))
            if not c:
                break
            i, n = 0, len(c)
            while i < n:
                if c[i] == 0:
                    if zrun == 0:
                        zstart = pos + i
                    zrun += 1
                    if zrun >= run:
                        return zstart
                else:
                    zrun = 0
                i += 1
            pos += n
        return None

    def sqlite_exact(self, off, mx):
        """Exact .sqlite size from the header: page_size @16 (u16be), page_count @28."""
        try:
            b = self.readat(off, 32)
            if len(b) < 32 or b[:16] != b"SQLite format 3\x00":
                return None
            ps = struct.unpack_from(">H", b, 16)[0]
            if ps == 1:
                ps = 65536
            if ps < 512 or ps > 65536 or (ps & (ps - 1)) != 0:
                return None
            pc = struct.unpack_from(">I", b, 28)[0]
            if pc == 0:
                return None
            sz = ps * pc
            return sz if 32 <= sz <= mx else None
        except (struct.error, IndexError):
            return None

    def ico_exact(self, off, mx):
        """Exact .ico size from the directory: max(entry.imgoff + entry.imglen)."""
        try:
            b = self.readat(off, 6)
            if len(b) < 6:
                return None
            cnt = struct.unpack_from("<H", b, 4)[0]
            if not (1 <= cnt <= 255):
                return None
            ent = self.readat(off + 6, cnt * 16)
            if len(ent) < cnt * 16:
                return None
            sz = 0
            for i in range(cnt):
                imglen = struct.unpack_from("<I", ent, i * 16 + 8)[0]
                imgoff = struct.unpack_from("<I", ent, i * 16 + 12)[0]
                sz = max(sz, imgoff + imglen)
            return sz if 6 <= sz <= mx else None
        except (struct.error, IndexError):
            return None

    def copy_range(self, off, size, outpath, hashobj=None):
        h = hashobj or hashlib.sha256()
        left = size
        with open(outpath, "wb") as o:
            while left > 0:
                c = self.readat(off + (size - left), min(CHUNK, left))
                if not c:
                    break
                o.write(c)
                h.update(c)
                left -= len(c)
        return h.hexdigest(), size - left

# ---------- carve ----------
def carve(image_path, outdir, only=None, audit_fp=None, resume=False):
    r = ImgReader(image_path)
    os.makedirs(outdir, exist_ok=True)
    try:  # start heartbeat: proves the run launched + when (post-mortem evidence)
        import datetime
        with open(os.path.join(outdir, "progress.txt"), "w") as hb:
            hb.write(f"started {datetime.datetime.now().isoformat()} pid={os.getpid()} total={r.total}\n")
    except OSError:
        pass
    sigs = [(e, h, f, m, mo) for (e, h, f, m, mo) in SIGS if not only or e in only]
    ckpt = os.path.join(outdir, "hits.json")
    if resume and r.total is not None and os.path.exists(ckpt):
        import json
        try:
            j = json.load(open(ckpt))
            if j.get("total") == r.total:
                hits = [tuple(h) for h in j["hits"]]
                dropped = j.get("dropped", 0)
                with open(os.path.join(outdir, "progress.txt"), "a") as hb:
                    hb.write(f"scan skipped (resume): {len(hits)} hits loaded from hits.json\n")
            else:
                hits = None
        except (ValueError, KeyError, OSError):
            hits = None
    else:
        hits = None
    if hits is None:
        hits, dropped, total = r.scan_headers(sigs)
        try:  # checkpoint: next sleep/reboot death resumes in seconds, not hours
            import json
            with open(ckpt, "w") as jf:
                json.dump({"total": r.total, "dropped": dropped,
                           "hits": [list(h) for h in hits]}, jf)
        except OSError:
            pass
    # heartbeat: phase-1 finished; report and flush so long runs show life
    try:
        with open(os.path.join(outdir, "progress.txt"), "a") as hb:
            hb.write(f"phase1 done: {len(hits)} hits, {dropped} dropped, {r.total if r.total is not None else total} bytes\n")
    except OSError:
        pass
    results, audit, manifest = [], [], []
    if dropped:
        audit.append(f"prefilter dropped {dropped} unvalidated weak hits")
    for n, (off, idx) in enumerate(hits):
        ext, hdr, ftr, mx, mode = sigs[idx]
        cstart = off  # where the file's bytes begin (box mode shifts to off-4)
        next_hdr = hits[n+1][0] if n+1 < len(hits) else (r.total if r.total is not None else (1 << 63))
        if ext == "bmp":
            b = r.readat(off, 6)
            fsize = struct.unpack_from("<I", b, 2)[0]
            end = fsize + off
            if r.total is not None:
                end = min(end, r.total)
            chopped = end != off + fsize
            size = max(0, end - off)
        elif mode.startswith("riff:"):
            end = r.riff_size(off, mode.split(":", 1)[1], mx)
            if end is None:
                continue
            size, chopped = end - off, False
        elif mode == "box":
            end = r.box_walk(off, mx, next_hdr)
            if end is None:
                audit.append(f"MP4 @{off}: no plausible box chain, skipped")
                continue
            chopped = False
            cstart = off - 4          # box files start at the SIZE prefix, 4 bytes before 'ftyp'
            size = end - cstart       # (v3-v4 bug: was end-off, silently dropped the prefix)
        elif ftr:
            min_len = 8 if ext in ("gif", "rtf") else 64
            cands = [e for e in r.find_footers(off, off + len(hdr), ftr, mx, min_len) if e - off >= min_len]
            if mode == "reverse":
                audit.append(f"PDF @{off}: {len(cands)} footers in range, using last")
            if not cands:
                if ext == "zip":
                    lim = r.total if r.total is not None else off + mx
                    end = min(off + mx, next_hdr, lim)
                    if end - off < 64:
                        continue
                    chopped, size = True, end - off
                    audit.append(f"ZIP @{off}: no EOCD, chopped at next_hdr={next_hdr}")
                else:
                    continue
            else:
                end = cands[-1] if mode == "reverse" else cands[0]
                chopped, size = False, end - off
                if ext == "pdf":
                    # PDF spec: up to 2 EOLs may follow %%EOF — absorb them
                    # (gauntlet-proven: without this every PDF lost its final byte)
                    trail = r.readat(end, 2)
                    if trail[:1] in (b"\n", b"\r"):
                        if trail[:2] == b"\r\n":
                            end += 2
                        else:
                            end += 1
                    size = end - off
                if ext == "zip":
                    size = size + 22
                    end = end + 22
                    if r.total is not None:  # clamp EOCD-comment overhang to EOF (keeps containment exact)
                        end = min(end, r.total)
                        size = end - off
        else:
            lim = r.total if r.total is not None else off + mx
            capped_end = min(off + mx, lim)  # the max-size GUESS (no real boundary)
            end = min(off + mx, next_hdr, lim)
            # format-aware sizing: exact where the header states it
            if ext == "sqlite":
                sz = r.sqlite_exact(off, mx)
                if sz:
                    end = min(off + sz, end)
            elif ext == "ico":
                sz = r.ico_exact(off, mx)
                if sz:
                    end = min(off + sz, end)
            # zero-gap stop: a >=64KB all-zero run means "file ended here".
            # Applies to every next-mode carve regardless of what bounded it —
            # empty space between files is not file content.
            if end - off > 64 * 1024:
                zg = r.zero_gap(off + 32, end)
                if zg is not None:
                    end = zg
            chopped, size = (end >= capped_end), max(0, end - off)
        if size < 8:
            continue
        if results and off >= results[-1][1] and end <= results[-1][2]:
            audit.append(f"SKIP @{off} {ext}: contained in {results[-1][0]}")
            continue
        fn = f"{n:04d}_{off:08d}.{ext}"
        digest, wrote = r.copy_range(cstart, size, os.path.join(outdir, fn))
        if wrote < size:
            audit.append(f"TRUNC @{off} {ext}: EOF after {wrote}/{size}")
            size = wrote
        results.append((fn, off, off + size, ext, chopped, size))
        manifest.append((fn, off, size, digest, "CHOPPED" if chopped else "ok"))
        audit.append(f"CARVED {fn} off={off} size={size} sha={digest[:12]} chopped={chopped}")
        try:  # heartbeat every carve: post-mortem evidence if the run dies
            with open(os.path.join(outdir, "progress.txt"), "a") as hb:
                hb.write(f"carved {fn} off={off} size={size}\n")
        except OSError:
            pass
    with open(os.path.join(outdir, "manifest.csv"), "w") as m:
        m.write("file,offset,size,sha256,status\n")
        for row in manifest:
            m.write(f"{row[0]},{row[1]},{row[2]},{row[3]},{row[4]}\n")
    if audit_fp:
        with open(audit_fp, "w") as a:
            a.write("\n".join(audit) + "\n")
    r.close()
    return results, (r.total if r.total is not None else total), audit

# ---------- frag pass (post-carve reassembly) ----------
def frag_pass(image_path, outdir, results):
    """Try stitching mp4/zip results. Returns [(fn, kind, detail)] for audit/manifest."""
    import zipfile as _zf
    made = []
    r = ImgReader(image_path)
    total = r.total
    man_lines = []
    for n, (fn, off, end, ext, chopped, size) in enumerate(results):
        stop_at = results[n+1][1] if n + 1 < len(results) else None
        if ext == "mp4":
            extents, gaps, score, complete = stitch_mp4(r, off, 4 * 1024 * MiB, total, stop_at=stop_at)
            asm_len = sum(ln for _, ln in extents)
            if score >= 4 and asm_len > size:
                out = os.path.join(outdir, fn.replace(".mp4", ".stitched.mp4"))
                h = hashlib.sha256()
                with open(out, "wb") as o:
                    for o2, ln in extents:
                        left = ln
                        while left > 0:
                            c = r.readat(o2 + (ln - left), min(CHUNK, left))
                            if not c:
                                break
                            o.write(c)
                            h.update(c)
                            left -= len(c)
                # validate assembly parses cleanly
                vr = ImgReader(out)
                vend, vtypes = walk_boxes(vr, 0, os.path.getsize(out), os.path.getsize(out))
                vr.close()
                if mp4_score(vtypes) >= 4 and vend == os.path.getsize(out):
                    digest = h.hexdigest()
                    man_lines.append((os.path.basename(out), 0, asm_len, digest, "stitched"))
                    made.append((os.path.basename(out), "mp4",
                                 f"{len(extents)} extents, {len(gaps)} gaps {gaps}, score={score}"))
                else:
                    os.remove(out)
        elif ext == "zip":
            res = stitch_zip(r, off, 512 * MiB, total)
            if res["ok"] and res["needed"]:
                out = os.path.join(outdir, fn.replace(".zip", ".stitched.zip"))
                with _zf.ZipFile(out, "w") as z:
                    for name, payload in res["files"].items():
                        z.writestr(name, payload)
                digest = sha256_of(open(out, "rb").read())
                man_lines.append((os.path.basename(out), 0, os.path.getsize(out), digest, "stitched"))
                made.append((os.path.basename(out), "zip",
                             f"{len(res['extents'])} extents, gaps {res['gaps']}"))
    r.close()
    if man_lines:
        with open(os.path.join(outdir, "manifest.csv"), "a") as m:
            for row in man_lines:
                m.write(f"{row[0]},{row[1]},{row[2]},{row[3]},{row[4]}\n")
    return made

# ---------- NTFS ----------
def parse_boot_fd(r):
    b = r.readat(0, 512)
    if len(b) < 512 or b[510:512] != b"\x55\xaa" or b[3:7] != b"NTFS":
        return None
    bps = struct.unpack_from("<H", b, 11)[0]
    spc = b[13]
    if bps not in (512, 1024, 2048, 4096) or spc == 0 or spc > 128:
        return None
    mft_lcn = struct.unpack_from("<Q", b, 48)[0]
    cs = bps * spc
    return {"bps": bps, "spc": spc, "cs": cs, "mft": mft_lcn * cs}

def parse_runs(blob):
    runs, i = [], 0
    while i < len(blob):
        hdr = blob[i]; i += 1
        if hdr == 0:
            break
        llen, loff = hdr & 0xF, hdr >> 4
        length = int.from_bytes(blob[i:i+llen], "little"); i += llen
        if loff == 0:
            runs.append((None, length))
            continue
        offb = blob[i:i+loff]; i += loff
        off = int.from_bytes(offb, "little")
        if offb[-1] & 0x80:
            off -= 1 << (8 * loff)
        runs.append((off, length))
    return runs

def resolve_runs(runs):
    out, cur = [], 0
    for off, ln in runs:
        if off is None:
            out.append((None, ln))
        else:
            cur += off
            out.append((cur, ln))
    return out

def parse_mft_record(buf, off):
    if len(buf) < off + 48 or buf[off:off+4] != b"FILE":
        return None
    seq = struct.unpack_from("<H", buf, off+16)[0]
    attr_off = struct.unpack_from("<H", buf, off+20)[0]
    flags = struct.unpack_from("<H", buf, off+22)[0]
    rec = {"off": off, "seq": seq, "flags": flags, "num": -1,
           "in_use": bool(flags & 1), "is_dir": bool(flags & 2),
           "names": [], "parent": None, "data_resident": None,
           "data_runs": [], "data_size": 0}
    p, end = off + attr_off, off + 1024
    for _ in range(32):
        if p + 8 > end or p + 8 > len(buf):
            break
        atype, alen = struct.unpack_from("<II", buf, p)
        if atype == 0xFFFFFFFF or alen == 0 or p + alen > len(buf):
            break
        nonres = buf[p+8]
        try:
            if atype == 0x30:
                vlen = struct.unpack_from("<I", buf, p+16)[0]
                voff = struct.unpack_from("<H", buf, p+20)[0]
                pref = struct.unpack_from("<Q", buf, p+voff)[0]
                rec["parent"] = pref & 0xFFFFFFFFFFFF
                nlen = buf[p+voff+64]
                nraw = buf[p+voff+66:p+voff+66+nlen*2]
                rec["names"].append((nraw.decode("utf-16-le", "replace"), pref))
            elif atype == 0x80 and buf[p+9] == 0:
                if nonres == 0:
                    vlen = struct.unpack_from("<I", buf, p+16)[0]
                    voff = struct.unpack_from("<H", buf, p+20)[0]
                    rec["data_resident"] = bytes(buf[p+voff:p+voff+vlen])
                    rec["data_size"] = struct.unpack_from("<Q", buf, p+48)[0] if alen >= 56 else vlen
                else:
                    roff = struct.unpack_from("<H", buf, p+32)[0]
                    rec["data_runs"] = resolve_runs(parse_runs(buf[p+roff:p+alen]))
                    rec["data_size"] = struct.unpack_from("<Q", buf, p+48)[0]
        except Exception:
            pass
        p += alen
    return rec

def walk_mft(r, boot, limit=300000):
    recs, base = [], boot["mft"]
    for i in range(limit):
        off = base + i * 1024
        buf = r.readat(off, 1024)
        if len(buf) < 48:
            break
        if buf[0:4] != b"FILE":
            if recs:
                break
            continue
        rec = parse_mft_record(buf, 0)
        if rec:
            rec["off"], rec["num"] = off, i
            recs.append(rec)
    return recs

def build_paths(recs):
    bynum = {x["num"]: x for x in recs}
    def path(x, depth=0):
        nm = x["names"][0][0] if x["names"] else f"MFT{x['num']}"
        p = x.get("parent")
        if depth > 64 or p is None or p == x["num"] or p not in bynum:
            return "/" if p == x["num"] else "/" + nm
        return path(bynum[p], depth+1).rstrip("/") + "/" + nm
    return {x["num"]: path(x) for x in recs}

def extract_record(r, rec, boot, outpath):
    if rec["data_resident"] is not None:
        blob = rec["data_resident"][:rec["data_size"] or None]
        open(outpath, "wb").write(blob)
        return blob, "resident"
    if not rec["data_runs"] or boot is None:
        return None, "none"
    h = hashlib.sha256()
    left, cs = rec["data_size"], boot["cs"]
    with open(outpath, "wb") as o:
        for coff, ln in rec["data_runs"]:
            if left <= 0:
                break
            want = min(ln * cs, left)
            if coff is None:
                o.write(b"\x00" * want)
                h.update(b"\x00" * want)
            else:
                got = 0
                while got < want:
                    c = r.readat(coff * cs + got, min(CHUNK, want - got))
                    if not c:
                        break
                    o.write(c)
                    h.update(c)
                    got += len(c)
            left -= want
    return h.hexdigest(), "runs"

def fls_all(image_path):
    """Auto-detect FS and list all entries. Returns (fs, records, extra)."""
    with open(image_path, "rb") as f:
        head = f.read(512)
    try:
        big = os.path.getsize(image_path) > (4 << 30)  # >4GB: no whole-image reads
    except OSError:
        big = False
    if len(head) >= 512 and head[510:512] == b"\x55\xaa":
        if head[3:11] == b"EXFAT   ":
            if big:
                return "exFAT(too large to enumerate)", [], None
            with open(image_path, "rb") as f:
                data = f.read()
            b = parse_exfat_boot(data)
            if b:
                recs = exfat_walk(data, b)
                return "exFAT", [{"num": -1, "off": -1, "is_dir": x["is_dir"], "path": x["path"],
                                  "deleted": x["deleted"], "size": x["size"], "date": x["date"],
                                  "_rec": x, "_boot": b} for x in recs], b
        elif True:  # try NTFS, fall back to FAT12/16/32
            r = ImgReader(image_path)
            boot = parse_boot_fd(r)
            if boot:
                recs = walk_mft(r, boot)
                paths = build_paths(recs)
                r.close()
                return "NTFS", [{"num": x["num"], "off": x["off"], "is_dir": x["is_dir"],
                                 "path": paths.get(x["num"], "(no-name)"), "deleted": not x["in_use"],
                                 "size": x["data_size"], "date": "", "_rec": x} for x in recs], boot
            r.close()
            if big:
                return "none (raw image, >4GB — FS scan skipped)", [], None
            with open(image_path, "rb") as f:
                data = f.read()
            b = parse_fat_boot(data)
            if b:
                recs = fat_walk(data, b)
                return b["kind"], [{"num": -1, "off": -1, "is_dir": x["is_dir"], "path": x["path"],
                                    "deleted": x["deleted"], "size": x["size"], "date": x["date"],
                                    "_rec": x, "_boot": b} for x in recs], b
    if big:
        return "none (raw image, >4GB — FS scan skipped)", [], None
    # small raw image: stray MFT record scan is affordable
    recs, boot, paths, _ = fls_mft(image_path)
    return ("NTFS" if boot else "raw",
            [{"num": -1, "off": x["off"], "is_dir": x["is_dir"],
              "path": (x["names"][0][0] if x["names"] else "(no-name)"), "deleted": not x["in_use"],
              "size": x["data_size"], "date": "", "_rec": x} for x in recs], boot)

def fls_mft(image_path):
    r = ImgReader(image_path)
    boot = parse_boot_fd(r)
    if boot:
        recs = walk_mft(r, boot)
        paths = build_paths(recs)
        r.close()
        return recs, boot, paths, None
    # raw scan for stray FILE records
    recs, pos = [], 0
    carry = b""
    while True:
        try:
            os.lseek(r.fd, pos, os.SEEK_SET)
            chunk = os.read(r.fd, CHUNK)
        except OSError:
            break
        if not chunk:
            break
        buf = carry + chunk
        base = pos - len(carry)
        s = 0
        while True:
            i = buf.find(b"FILE", s)
            if i == -1:
                break
            rec = parse_mft_record(r.readat(base + i, 1024), 0)
            if rec:
                rec["off"] = base + i
                recs.append(rec)
            s = i + 1
        pos += len(chunk)
        carry = buf[-8:]
    r.close()
    return recs, None, {}, None

# ---------- disk imager (ddrescue-style, resume-able) ----------
def load_map(mp, block, total):
    """Read a .map from an earlier run. Returns per-block status or None (fresh)."""
    try:
        lines = open(mp).read().splitlines()
    except OSError:
        return None
    try:
        hdr = lines[0].split(":", 1)[1].split()
        kv = dict(x.split("=") for x in hdr)
        if int(kv["block"]) != block or int(kv["total"]) != total:
            return None  # geometry changed -> start fresh
        n = (total + block - 1) // block
    except (IndexError, ValueError, KeyError):
        return None
    status = bytearray(b"?" * n)
    for ln in lines[1:]:
        try:
            off, sz, st = ln.split()
            # one map line may span many blocks (merged runs) — expand it
            first, last = int(off) // block, (int(off) + int(sz) - 1) // block
            for bi in range(max(0, first), min(n, last + 1)):
                if st[0] in "+-?":
                    status[bi] = ord(st[0])
        except ValueError:
            continue
    return status

def clone_disk(src, dst, block=MiB, retries=3, map_path=None, reverse=True, fresh=False):
    try:
        total = os.path.getsize(src)
    except OSError:
        total = None
    if total is None:
        raise ValueError("live-drive imaging needs --size (drive size unknown)")
    n = (total + block - 1) // block
    mp = map_path or (dst + ".map")
    status = bytearray(b"?" * n)
    skipped = 0
    if not fresh:
        prior = load_map(mp, block, total)
        if prior is not None and len(prior) == n:
            status = prior
            skipped = sum(1 for s in status if s == ord("+"))
    fi = os.open(src, os.O_RDONLY | OBIN)
    # NOTE: no O_TRUNC — a resumed run must keep bytes from the previous pass
    fo = os.open(dst, os.O_WRONLY | os.O_CREAT | OBIN)
    try:
        if os.fstat(fo).st_size != total:
            os.ftruncate(fo, total)
    except OSError:
        pass
    def attempt(bi):
        for _ in range(retries):
            try:
                os.lseek(fi, bi * block, os.SEEK_SET)
                chunk = os.read(fi, min(block, total - bi * block))
                if not chunk:
                    return False
                os.lseek(fo, bi * block, os.SEEK_SET)
                os.write(fo, chunk)
                return True
            except OSError:
                continue
        return False
    good = bad = 0
    for bi in range(n):
        if status[bi] == ord("+"):
            good += 1  # trusted from map, not re-read
            continue
        if attempt(bi):
            status[bi] = ord("+"); good += 1
        else:
            status[bi] = ord("-"); bad += 1
    if reverse:
        for bi in range(n-1, -1, -1):
            if status[bi] == ord("-") and attempt(bi):
                status[bi] = ord("+"); good += 1; bad -= 1
    os.close(fi); os.close(fo)
    with open(mp, "w") as m:
        m.write(f"# surrect map: block={block} total={total}\n")
        run_i = 0
        for i in range(1, n):
            if status[i] != status[run_i]:
                m.write(f"{run_i*block} {min(i*block, total)-run_i*block} {chr(status[run_i])}\n")
                run_i = i
        m.write(f"{run_i*block} {total-run_i*block} {chr(status[run_i])}\n")
    return {"total": total, "good": good, "bad": bad, "blocks": n, "map": mp,
            "skipped": skipped, "resumed": skipped > 0}

# ---------- FAT12/16/32 ----------
def parse_fat_boot(data):
    if len(data) < 512 or data[510:512] != b"\x55\xaa":
        return None
    if data[3:11] == b"EXFAT   ":
        return None  # handled by exFAT parser
    try:
        bps = struct.unpack_from("<H", data, 11)[0]
        spc = data[13]
        rsv = struct.unpack_from("<H", data, 14)[0]
        fats = data[16]
        root_ents = struct.unpack_from("<H", data, 17)[0]
        spf = struct.unpack_from("<H", data, 22)[0] or struct.unpack_from("<I", data, 36)[0]
        tot = struct.unpack_from("<H", data, 19)[0] or struct.unpack_from("<I", data, 32)[0]
        root_cl = struct.unpack_from("<I", data, 44)[0]
        if bps not in (512, 1024, 2048, 4096) or not spc or not fats or not spf:
            return None
        if not tot:
            tot = len(data) // bps
        root_secs = ((root_ents * 32) + (bps - 1)) // bps
        first_data = (rsv + fats * spf + root_secs) * bps
        ncl = (tot - (rsv + fats * spf + root_secs)) // spc
        dt = 12 if ncl < 4085 else (16 if ncl < 65525 else 32)
        return {"kind": f"FAT{dt}", "dt": dt, "bps": bps, "spc": spc, "cs": bps * spc,
                "fat_off": rsv * bps, "first_data": first_data, "root_ents": root_ents,
                "root_off": (rsv + fats * spf) * bps if dt != 32 else None, "root_cl": root_cl}
    except (struct.error, IndexError):
        return None

def fat_next(data, b, cl):
    try:
        if b["dt"] == 12:
            o = b["fat_off"] + cl * 3 // 2
            v = struct.unpack_from("<H", data, o)[0]
            v = v >> 4 if cl & 1 else v & 0xFFF
            return None if v >= 0xFF8 else (None if v == 0 else v)
        if b["dt"] == 16:
            v = struct.unpack_from("<H", data, b["fat_off"] + cl * 2)[0]
            return None if v >= 0xFFF8 else (None if v == 0 else v)
        v = struct.unpack_from("<I", data, b["fat_off"] + cl * 4)[0] & 0x0FFFFFFF
        return None if v >= 0x0FFFFFF8 else (None if v == 0 else v)
    except (struct.error, IndexError):
        return None

def fat_cl_off(b, cl):
    return b["first_data"] + (cl - 2) * b["cs"]

def fat_chain(data, b, start, size):
    """Follow cluster chain up to size bytes. Returns bytes (stops at EOC/loop)."""
    out, seen, cl = bytearray(), set(), start
    while len(out) < size and cl is not None and cl >= 2 and cl not in seen and len(seen) < 1 << 20:
        seen.add(cl)
        o = fat_cl_off(b, cl)
        out += data[o:o + min(b["cs"], size - len(out))]
        cl = fat_next(data, b, cl)
    return bytes(out[:size])

def fat_dosdate(d, t):
    try:
        return f"{((d >> 9) & 0x7F) + 1980:04d}-{((d >> 5) & 0xF):02d}-{(d & 0x1F):02d} {(t >> 11) & 0x1F:02d}:{((t >> 5) & 0x3F):02d}"
    except Exception:
        return ""

def fat_lfn_name(parts):
    raw = b"".join(parts)
    return raw.decode("utf-16-le", "replace").split("\x00")[0]

def fat_walk(data, b):
    """Returns [{path, size, start, deleted, is_dir, date}]. LFN-aware, 0xE5-aware."""
    recs = []
    def emit_dir(buf, path):
        lfns, i = [], 0
        while i + 32 <= len(buf):
            e = buf[i:i+32]
            if e[0] == 0x00:
                break
            attr = e[11]
            if attr == 0x0F or (e[0] == 0xE5 and attr == 0x0F):
                # LFN part. Disk order is descending seq; name order is ascending.
                # A deleted set loses one seq byte (0xE5); it was first on disk
                # = highest seq = tail of the name, so sort it last.
                seq = e[0] if e[0] != 0xE5 else 0xFF
                chars = e[1:11] + e[14:26] + e[28:32]
                lfns.append((seq & 0xFF, chars))
                i += 32
                continue
            if attr == 0x08:  # volume label
                lfns = []
                i += 32
                continue
            deleted = e[0] == 0xE5
            if lfns:
                name = fat_lfn_name([c for _, c in sorted(lfns)])
                if deleted:
                    name = "?" + name[1:] if len(name) > 1 else "?"
            else:
                base = (bytes([0x5F]) + e[1:8] if deleted else e[0:8]).decode("ascii", "replace").rstrip()
                ext = e[8:11].decode("ascii", "replace").rstrip()
                name = base + ("." + ext if ext else "")
                if not name.strip("? "):
                    lfns = []
                    i += 32
                    continue
            start = struct.unpack_from("<H", e, 26)[0]
            if b["dt"] == 32:
                start |= struct.unpack_from("<H", e, 20)[0] << 16
            size = struct.unpack_from("<I", e, 28)[0]
            is_dir = bool(attr & 0x10)
            date = fat_dosdate(struct.unpack_from("<H", e, 24)[0], struct.unpack_from("<H", e, 22)[0])
            full = path.rstrip("/") + "/" + name
            recs.append({"path": full, "size": 0 if is_dir else size, "start": start,
                         "deleted": deleted, "is_dir": is_dir, "date": date})
            if is_dir and not deleted and name not in (".", "..") and start >= 2:
                emit_dir(fat_chain(data, b, start, 4*MiB), full)
            elif is_dir and deleted and start >= 2:
                # deleted dir: best effort, contiguous clusters by size unknown -> skip descend
                pass
            lfns = []
            i += 32
    if b["dt"] == 32:
        emit_dir(fat_chain(data, b, b["root_cl"] or 2, 4*MiB), "")
    else:
        emit_dir(data[b["root_off"]:b["root_off"] + b["root_ents"] * 32], "")
    return recs

def fat_extract(data, b, rec):
    if rec["is_dir"] or rec["start"] < 2:
        return None
    # live file: follow chain; deleted: FAT zeroed -> contiguous approximation
    if rec["deleted"]:
        o = fat_cl_off(b, rec["start"])
        return data[o:o + rec["size"]]
    return fat_chain(data, b, rec["start"], rec["size"])

# ---------- exFAT ----------
def parse_exfat_boot(data):
    if len(data) < 512 or data[510:512] != b"\x55\xaa" or data[3:11] != b"EXFAT   ":
        return None
    try:
        bps = 1 << data[108]
        spc = 1 << data[109]
        fat_off = struct.unpack_from("<I", data, 80)[0] * bps
        heap_off = struct.unpack_from("<I", data, 88)[0] * bps
        root_cl = struct.unpack_from("<I", data, 96)[0]
        if bps not in (512, 1024, 2048, 4096) or not spc or root_cl < 2:
            return None
        return {"kind": "exFAT", "bps": bps, "cs": bps * spc, "fat_off": fat_off,
                "heap_off": heap_off, "root_cl": root_cl}
    except (struct.error, IndexError):
        return None

def exfat_cl_off(b, cl):
    return b["heap_off"] + (cl - 2) * b["cs"]

def exfat_next(data, b, cl):
    try:
        v = struct.unpack_from("<I", data, b["fat_off"] + cl * 4)[0]
        return None if v >= 0xFFFFFFF8 else (None if v == 0 else v)
    except (struct.error, IndexError):
        return None

def exfat_read_chain(data, b, start, maxlen, nofat=False):
    out, seen, cl = bytearray(), set(), start
    if nofat:  # contiguous
        return data[exfat_cl_off(b, start):exfat_cl_off(b, start) + maxlen]
    while len(out) < maxlen and cl is not None and cl >= 2 and cl not in seen and len(seen) < 1 << 20:
        seen.add(cl)
        o = exfat_cl_off(b, cl)
        out += data[o:o + min(b["cs"], maxlen - len(out))]
        cl = exfat_next(data, b, cl)
    return bytes(out[:maxlen])

def exfat_walk(data, b):
    recs = []
    def emit_dir(buf, path):
        i = 0
        while i + 32 <= len(buf):
            t = buf[i]
            if t == 0x00:
                break
            base_t = t & 0x7F
            deleted = not (t & 0x80)
            if base_t == 0x05:  # file set: 0x85 live, 0x05 deleted
                nsec = buf[i+1]
                attrs = struct.unpack_from("<H", buf, i+4)[0]
                stream, name, j = None, [], i + 32
                for _ in range(nsec):
                    if j + 32 > len(buf):
                        break
                    st = buf[j] & 0x7F
                    if st == 0x40:  # stream: 0xC0 live, 0x40 deleted
                        stream = buf[j:j+32]
                    elif st == 0x41:  # name: 0xC1 live, 0x41 deleted
                        name.append(buf[j+2:j+32])
                    j += 32
                if stream is None:
                    i += 32
                    continue
                is_dir = bool(attrs & 0x10)
                nm = b"".join(name).decode("utf-16-le", "replace").split("\x00")[0]
                start = struct.unpack_from("<I", stream, 20)[0]
                size = struct.unpack_from("<Q", stream, 8)[0]  # ValidDataLength
                full = path.rstrip("/") + "/" + (nm or "(no-name)")
                recs.append({"path": full, "size": 0 if is_dir else size, "start": start,
                             "deleted": deleted, "is_dir": is_dir,
                             "nofat": bool(stream[1] & 0x02), "date": ""})
                if is_dir and not deleted and start >= 2:
                    nofat = bool(stream[1] & 0x02)
                    emit_dir(exfat_read_chain(data, b, start, 4*MiB, nofat), full)
                i = j
                continue
            i += 32
    emit_dir(exfat_read_chain(data, b, b["root_cl"], 4*MiB), "")
    return recs

def exfat_extract(data, b, rec):
    if rec["is_dir"] or rec["start"] < 2:
        return None
    if rec.get("nofat") or rec["deleted"]:
        o = exfat_cl_off(b, rec["start"])
        return data[o:o + rec["size"]]
    return exfat_read_chain(data, b, rec["start"], rec["size"])

# ---------- fragment reassembly ----------
MP4_KNOWN = {b"ftyp", b"moov", b"mdat", b"moof", b"free", b"skip", b"wide",
             b"trak", b"mdia", b"minf", b"stbl", b"mvhd", b"tkhd", b"mvex",
             b"trex", b"edts", b"udta", b"meta", b"uuid", b"mfra", b"styp",
             b"sidx", b"emsg", b"vmhd", b"smhd", b"hmhd", b"dinf", b"dref",
             b"stsd", b"avc1", b"mp4a", b"esds", b"avcC", b"elst", b"iods"}

def box_at(reader, pos, total):
    """Returns (size, type) if a plausible box header sits at pos, else None."""
    b = reader.readat(pos, 16)
    if len(b) < 8:
        return None
    sz = struct.unpack_from(">I", b)[0]
    typ = bytes(b[4:8])
    if sz == 1:
        if len(b) < 16:
            return None
        sz = struct.unpack_from(">Q", b, 8)[0]
        if sz < 16 or (total is not None and pos + sz > total + 16):
            return None
    elif sz < 8 or sz > (1 << 31):
        return None
    elif total is not None and pos + sz > total and sz != 0:
        return None
    if not all(0x20 <= c < 0x7F for c in typ):
        return None
    return (sz, typ)

def box_confirmed(reader, pos, total):
    """Candidate rule (deliberately permissive): a plausible header here AND a
    plausible header right after it, OR a known box type on its own. Decoy
    rejection happens at assembly validation, not here."""
    first = box_at(reader, pos, total)
    if not first:
        return None
    sz, typ = first
    if sz == 0:
        return (sz, typ, True) if typ in MP4_KNOWN else None
    if box_at(reader, pos + sz, total):
        return (sz, typ, True)
    return (sz, typ, True) if typ in MP4_KNOWN else None

def walk_boxes(reader, pos, hard, total):
    """Walk chained boxes; stop at first unconfirmed header. Returns (endpos, types)."""
    types = set()
    while pos + 8 <= hard:
        hit = box_confirmed(reader, pos, total)
        if not hit:
            break
        sz, typ, _ = hit
        if sz == 0:
            return hard, types | {typ}
        types.add(typ)
        pos += sz
    return pos, types

def gap_candidates(reader, stall, window, hard, total, stop_at, cap=64):
    """Candidate box starts in [stall, stall+window). Fast path: memchr sweep for
    KNOWN box types in-chunk, full box_confirmed only at those rare positions.
    (Gauntlet-proven: the old byte-by-byte probe was ~1 syscall/byte -> hours.)"""
    out, scanned = [], 0
    lim = hard if stop_at is None else min(hard, stop_at)
    while scanned < window and stall + scanned + 8 <= lim and len(out) < cap:
        wstart = stall + scanned
        w = reader.readat(wstart, min(CHUNK, lim - wstart))
        if not w:
            break
        for t in MP4_KNOWN:
            s = 0
            while len(out) < cap:
                i = w.find(t, s)
                if i == -1:
                    break
                if i >= 4:
                    cand = wstart + i - 4  # size prefix precedes the type
                    if cand >= stall and box_confirmed(reader, cand, total):
                        # a valid MP4 has exactly ONE ftyp, at the start:
                        # a mid-assembly 'ftyp' candidate is a decoy by definition
                        if reader.readat(cand + 4, 4) == b"ftyp":
                            s = i + 1
                            continue
                        out.append(cand)
                s = i + 1
        scanned += max(1, len(w))
    return sorted(set(out))

def mp4_score(types):
    return (1 if b"ftyp" in types else 0) + (2 if b"moov" in types else 0) + \
           (1 if (b"mdat" in types or b"moof" in types) else 0)

def stitch_mp4(reader, start, mx, total, window=64*MiB, stop_at=None, max_gaps=2, budget=2000):
    """Box-boundary stitching from an 'ftyp' offset with backtracking.
    Tries gap bridges in order; keeps the best-validated assembly.
    Returns (extents[(off,len)], gaps[(off,len)], score, complete)."""
    if reader.readat(start, 4) != b"ftyp":
        return [], [], 0, False
    seg0 = start - 4
    hard = seg0 + mx if total is None else min(seg0 + mx, total)
    if stop_at is not None:
        hard = min(hard, stop_at)
    end0, types0 = walk_boxes(reader, seg0, hard, total)
    if b"ftyp" not in types0:
        return [], [], 0, False
    # assemblies: (extents, gaps, types) — depth-first over bridge choices.
    # Objective: (type score, recovered bytes, fewer gaps). Bytes matter: a
    # split that leaves part1 with ftyp+moov+mdat adds no NEW types when
    # bridged, and a type-only objective would keep the truncated part1
    # (gauntlet-proven: 0/20 until bytes entered the key).
    best = ([(seg0, end0 - seg0)] if end0 > seg0 else [], [], set(types0))
    stack = [(end0, set(types0),
              [(seg0, end0 - seg0)] if end0 > seg0 else [], [])]
    spent = 0
    while stack and spent < budget:
        pos, types, extents, gaps = stack.pop()
        if len(gaps) >= max_gaps or pos + 8 > hard:
            continue
        for cand in gap_candidates(reader, pos, window, hard, total, stop_at, cap=16):
            if cand <= pos or spent >= budget:
                continue
            spent += 1
            cend, ctypes = walk_boxes(reader, cand, hard, total)
            if cend <= cand:
                continue
            ne = extents + [(cand, cend - cand)]
            ng = gaps + [(pos, cand - pos)]
            nt = types | ctypes
            if key_of(nt, ne, ng) > key_of(best[2], best[0], best[1]):
                best = (ne, ng, nt)
            stack.append((cend, nt, ne, ng))
    extents, gaps, types = best
    score = mp4_score(types)
    return extents, gaps, score, (score >= 4 and not gaps)

def key_of(types, extents, gaps):
    return (mp4_score(types), sum(l for _, l in extents), -len(gaps))

def zip_parse_eocd(buf, eocd_off):
    """Parse EOCD at eocd_off (offset within buf). Returns (central_off, central_size, count) or None."""
    try:
        if buf[eocd_off:eocd_off+4] != b"PK\x05\x06":
            return None
        count = struct.unpack_from("<H", buf, eocd_off+10)[0]
        size = struct.unpack_from("<I", buf, eocd_off+12)[0]
        off = struct.unpack_from("<I", buf, eocd_off+16)[0]
        return off, size, count
    except (struct.error, IndexError):
        return None

def zip_parse_central(buf):
    """Parse ALL PK\\x01\\x02 entries in buf. Returns [{name, method, crc, csize, usize, local_off}]."""
    out, i = [], 0
    while True:
        i = buf.find(b"PK\x01\x02", i)
        if i == -1 or i + 46 > len(buf):
            break
        try:
            method = struct.unpack_from("<H", buf, i+10)[0]
            crc = struct.unpack_from("<I", buf, i+16)[0]
            csize = struct.unpack_from("<I", buf, i+20)[0]
            usize = struct.unpack_from("<I", buf, i+24)[0]
            nlen = struct.unpack_from("<H", buf, i+28)[0]
            elen = struct.unpack_from("<H", buf, i+30)[0]
            clen = struct.unpack_from("<H", buf, i+32)[0]
            loff = struct.unpack_from("<I", buf, i+42)[0]
            name = bytes(buf[i+46:i+46+nlen]).decode("utf-8", "replace")
            out.append({"name": name, "method": method, "crc": crc, "csize": csize,
                        "usize": usize, "local_off": loff})
            i += 46 + nlen + elen + clen
        except (struct.error, IndexError):
            i += 4
    return out

def zip_find_locals(buf):
    """Find local headers PK\\x03\\x04 with names. Returns [{off, name, method, data_start}]."""
    out, i = [], 0
    while True:
        i = buf.find(b"PK\x03\x04", i)
        if i == -1 or i + 30 > len(buf):
            break
        try:
            method = struct.unpack_from("<H", buf, i+8)[0]
            nlen = struct.unpack_from("<H", buf, i+26)[0]
            elen = struct.unpack_from("<H", buf, i+28)[0]
            name = bytes(buf[i+30:i+30+nlen]).decode("utf-8", "replace")
            out.append({"off": i, "name": name, "method": method, "data_start": i+30+nlen+elen})
            i += 4
        except (struct.error, IndexError):
            i += 4
    return out

def zip_verify_entry(data, csize, usize, method, crc):
    """data: candidate raw bytes. Returns True if CRC/inflate validates."""
    try:
        import zlib, binascii
        if method == 0:
            return (binascii.crc32(data) & 0xFFFFFFFF) == crc and len(data) == csize
        if method == 8:
            if len(data) != csize or csize > 256 * MiB:
                return False
            raw = zlib.decompressobj(-15).decompress(bytes(data))
            return len(raw) == usize and (binascii.crc32(raw) & 0xFFFFFFFF) == crc
    except Exception:
        pass
    return False

def stitch_zip(reader, start, mx, total):
    """CRC-proven bridging for zips whose entry data is interrupted by foreign files.
    Straight-verifies first (common case: nothing to do). On failure, bridges
    intruders and re-verifies every entry; output is a FRESH valid archive
    repacked from verified payloads (original offsets can't be trusted).
    Returns dict {extents, gaps, files{name:bytes}, ok, needed}."""
    import binascii
    lim = start + mx if total is None else min(start + mx, total)
    head = reader.readat(start, min(4 * MiB, lim - start))
    eocds = []
    s = 0
    while True:
        i = head.find(b"PK\x05\x06", s)
        if i == -1:
            break
        eocds.append(start + i)
        s = i + 1
    if not eocds:
        for e in reader.find_footers(start, b"PK\x05\x06", mx, 22):
            eocds.append(e - 6)
            break
    if not eocds:
        return {"extents": [], "gaps": [], "files": {}, "ok": False, "needed": False}
    eocd = eocds[0]
    cbuf = reader.readat(max(start, eocd - (1 << 20)), eocd - max(start, eocd - (1 << 20)) + 22)
    central = zip_parse_central(cbuf)
    if not central:
        return {"extents": [], "gaps": [], "files": {}, "ok": False, "needed": False}
    span = reader.readat(start, min(eocd + 22 - start, 8 * MiB))
    locals_ = zip_find_locals(span)
    by_name = {}
    for lh in locals_:
        by_name.setdefault(lh["name"], []).append(lh)

    def entry_data(lh, need):
        return reader.readat(start + lh["data_start"], need)

    def verify_straight():
        payloads = {}
        for ce in central:
            cands = by_name.get(ce["name"], [])
            if not cands:
                return None
            blob = entry_data(cands[0], ce["csize"])
            if len(blob) < ce["csize"]:
                return None
            if not zip_verify_entry(blob, ce["csize"], ce["usize"], ce["method"], ce["crc"]):
                return None
            payloads[ce["name"]] = zip_payload(blob, ce)
            if payloads[ce["name"]] is None:
                return None
        return payloads

    straight = verify_straight()
    if straight is not None:
        ds = start + locals_[0]["data_start"] if locals_ else start
        return {"extents": [(start, eocd + 22 - start)], "gaps": [], "files": straight,
                "ok": True, "needed": False}
    # bridge pass: for each failing entry, skip intruding foreign files
    extents, gaps, payloads = [], [], {}
    ok = True
    for ce in central:
        cands = by_name.get(ce["name"], [])
        if not cands:
            ok = False
            break
        lh = cands[0]
        ds = start + lh["data_start"]
        need = ce["csize"]
        blob = reader.readat(ds, need)
        if len(blob) == need and zip_verify_entry(blob, ce["csize"], ce["usize"], ce["method"], ce["crc"]):
            extents.append((ds, need))
            payloads[ce["name"]] = zip_payload(blob, ce)
            continue
        # find intruding headers inside this entry's span; try skipping them
        # ONE at a time (then pairs) with CRC/inflate as judge, so false
        # 2-byte hits inside random data can never win.
        intruders = []
        for (e2, h2, f2, m2, mo2) in SIGS:
            if e2 == "zip":
                continue
            for hend in reader.find_footers(ds, ds, h2, need + 1024, len(h2)):
                hs = hend - len(h2)
                if not (ds <= hs < ds + need):
                    continue
                if f2:
                    ends = reader.find_footers(hs, hs + len(h2), f2, need + (1 << 20), len(f2), cap=1)
                    if not ends:
                        continue
                    intruders.append((hs, ends[0], True))
                else:
                    intruders.append((hs, hs + 8, False))
        # footer-paired (genuine files) first, then widest span
        intruders.sort(key=lambda t: (not t[2], -(t[1] - t[0])))
        won = False
        for (hs, he, _) in intruders[:8]:
            first = hs - ds
            if first < 0 or first >= need:
                continue
            cand = reader.readat(ds, first) + reader.readat(he, need - first)
            if len(cand) < need:
                continue
            cand = cand[:need]
            if zip_verify_entry(cand, ce["csize"], ce["usize"], ce["method"], ce["crc"]):
                extents += [(ds, first), (he, need - first)]
                gaps.append((hs, he - hs))
                payloads[ce["name"]] = zip_payload(cand, ce)
                won = True
                break
        if not won:
            for a in range(min(len(intruders), 6)):
                for b in range(a + 1, min(len(intruders), 6)):
                    (hs1, he1, _), (hs2, he2, _) = intruders[a], intruders[b]
                    if not (ds <= hs1 < he1 <= hs2 < he2):
                        continue
                    cand = reader.readat(ds, hs1 - ds) + reader.readat(he1, hs2 - he1) + \
                        reader.readat(he2, need - (hs1 - ds) - (hs2 - he1))
                    if len(cand) < need:
                        continue
                    cand = cand[:need]
                    if zip_verify_entry(cand, ce["csize"], ce["usize"], ce["method"], ce["crc"]):
                        extents += [(ds, hs1 - ds), (he1, hs2 - he1),
                                    (he2, need - (hs1 - ds) - (hs2 - he1))]
                        gaps += [(hs1, he1 - hs1), (hs2, he2 - hs2)]
                        payloads[ce["name"]] = zip_payload(cand, ce)
                        won = True
                        break
                if won:
                    break
        if not won:
            ok = False
            break
    if not ok:
        return {"extents": [], "gaps": gaps, "files": {}, "ok": False, "needed": True}
    return {"extents": sorted(set(extents)), "gaps": gaps, "files": payloads, "ok": True, "needed": True}

def zip_payload(blob, ce):
    """Decompressed payload bytes (None on failure)."""
    try:
        if ce["method"] == 0:
            return bytes(blob[:ce["usize"] or None])
        if ce["method"] == 8:
            import zlib
            return zlib.decompressobj(-15).decompress(bytes(blob))
    except Exception:
        pass
    return None

# ---------- drives (Windows) ----------
def smart_by_letter():
    """Map drive letter -> (health, tempC|''). Best-effort WMI/PowerShell, never raises."""
    try:
        import json, subprocess
        ps = (
            "$pd=@{}; "
            "Get-PhysicalDisk | ForEach-Object { $pd[$_.DeviceId]=$_.HealthStatus }; "
            "Get-Disk | ForEach-Object { "
            "  $n=$_.Number; $h=$pd[$n.ToString()]; "
            "  if (-not $h) { $h=$_.HealthStatus }; "
            "  Get-Partition -DiskNumber $n -ErrorAction SilentlyContinue | "
            "  Where-Object { $_.DriveLetter } | ForEach-Object { "
            "    [pscustomobject]@{L=($_.DriveLetter+':');H=$h} } } | ConvertTo-Json"
        )
        p = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, timeout=30)
        data = json.loads(p.stdout) if p.stdout.strip() else []
        if isinstance(data, dict):
            data = [data]
        out = {}
        for row in data:
            try:
                out[row["L"]] = (str(row.get("H") or "Unknown"), "")
            except (KeyError, TypeError):
                continue
        # temperature: SMART attr 194 via root\\wmi (best effort, often needs admin)
        try:
            ps2 = ("Get-WmiObject -Namespace root\\wmi -Class MSStorageDriver_ATAPISmartData "
                   "| Select-Object InstanceName,VendorSpecific | ConvertTo-Json")
            p2 = subprocess.run(["powershell", "-NoProfile", "-Command", ps2],
                                capture_output=True, text=True, timeout=30)
            d2 = json.loads(p2.stdout) if p2.stdout.strip() else []
            if isinstance(d2, dict):
                d2 = [d2]
            temps = {}
            for row in d2:
                vs = row.get("VendorSpecific") or []
                for i in range(2, min(len(vs), 2 + 30 * 12), 12):
                    if vs[i] == 194 and i + 5 < len(vs):
                        temps[str(row.get("InstanceName") or "")] = str(vs[i+5])
            out["_smart_instances"] = temps
        except Exception:
            pass
        return out
    except Exception:
        return {}

def list_drives():
    out = []
    try:
        import ctypes
        k = ctypes.windll.kernel32
        mask = k.GetLogicalDrives()
        for i in range(26):
            if mask & (1 << i):
                L = chr(65 + i) + ":"
                t = k.GetDriveTypeW(L + "\\")
                typ = {0: "unknown", 1: "noroot", 2: "removable", 3: "fixed", 4: "remote", 5: "cdrom", 6: "ramdisk"}.get(t, "?")
                total = ctypes.c_ulonglong(0); free = ctypes.c_ulonglong(0)
                sz = ""
                if k.GetDiskFreeSpaceExW(L + "\\", None, ctypes.byref(total), ctypes.byref(free)):
                    sz = str(total.value)
                out.append((L, typ, sz))
    except Exception as e:
        return [f"error|{e}|"]
    health = smart_by_letter()
    lines = []
    for L, typ, sz in out:
        h, tmp = health.get(L, ("Unknown", ""))
        lines.append(f"{L}|{typ}|{sz}|{h}|{tmp}")
    return lines

def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="surrect v4: carver + NTFS recovery + imager + live drives")
    ap.add_argument("image", nargs="?", help="image file or live drive (\\\\.\\E:)")
    ap.add_argument("-o", "--outdir", default="recovered")
    ap.add_argument("--only", default=None)
    ap.add_argument("--fls", action="store_true", help="list files with paths (fls -r -d)")
    ap.add_argument("--fls-json", action="store_true", help="same listing as one JSON line")
    ap.add_argument("--frag", action="store_true", help="post-carve fragment reassembly (mp4/zip)")
    ap.add_argument("--resume", action="store_true", help="reuse hits.json checkpoint (skip the phase-1 scan)")
    ap.add_argument("--fcat", default=None, metavar="PATH", help="extract FAT/exFAT file by path")
    ap.add_argument("--icat", type=int, default=None, metavar="MFT_OFF")
    ap.add_argument("--rec", type=int, default=None, metavar="MFT_NUM")
    ap.add_argument("--clone", nargs=2, default=None, metavar=("SRC", "DST"))
    ap.add_argument("--fresh", action="store_true", help="ignore existing .map, start clone over")
    ap.add_argument("--block", type=int, default=MiB)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--list-drives", action="store_true")
    ap.add_argument("--is-admin", action="store_true")
    a = ap.parse_args()
    if a.list_drives:
        print("admin=" + str(is_admin()))
        for line in list_drives():
            print(line)
        return
    if a.is_admin:
        print(str(is_admin()))
        return
    if a.clone:
        try:
            r = clone_disk(a.clone[0], a.clone[1], a.block, a.retries, fresh=a.fresh)
        except FileNotFoundError:
            print(f"cannot open '{a.clone[0]}' — no such drive or file (drives look like \\\\.\\C:).")
            return
        except PermissionError:
            print(f"access denied opening '{a.clone[0]}' — right-click Surrect -> Run as administrator, then retry.")
            return
        tag = f"resumed ({r['skipped']} skipped), " if r["resumed"] else ""
        print(f"cloned {r['total']} bytes: {tag}{r['good']}/{r['blocks']} blocks ok, {r['bad']} bad -> map {r['map']}")
        return
    if not a.image:
        ap.error("image required (file or \\\\.\\X:) or use --clone SRC DST")
    only = a.only.split(",") if a.only else None
    audit_path = os.path.join(a.outdir, "audit.txt")
    try:
        results, total, audit = carve(a.image, a.outdir, only, audit_path, resume=a.resume)
    except FileNotFoundError:
        print(f"cannot open '{a.image}' — no such drive or file (drives look like \\\\.\\C:).")
        return
    except PermissionError:
        print(f"access denied opening '{a.image}' — right-click Surrect -> Run as administrator, then retry.")
        return
    print(f"scanned {total} bytes, {len(results)} files -> {a.outdir}/ (manifest.csv + audit.txt)")
    for fn, off, end, ext, chopped, size in results:
        print(f"  {fn} off={off} size={size} [{'CHOPPED' if chopped else 'ok'}]")
    if a.frag:
        for fn, kind, detail in frag_pass(a.image, a.outdir, results):
            line = f"STITCHED {fn} [{kind}] {detail}"
            print(f"  {line}")
            audit.append(line)
        with open(audit_path, "w") as af:
            af.write("\n".join(audit) + "\n")
    try:
        fs, records, boot = fls_all(a.image)
    except FileNotFoundError:
        print(f"cannot open '{a.image}' — no such drive or file (drives look like \\\\.\\C:).")
        return
    except PermissionError:
        print(f"access denied opening '{a.image}' — right-click Surrect -> Run as administrator, then retry.")
        return
    ndel = sum(1 for r in records if r["deleted"])
    print(f"FS ({fs}): {len(records)} records, {ndel} deleted")
    if a.fls_json:
        import json
        print(json.dumps({"fs": fs, "records": [
            {k: v for k, v in r.items() if not k.startswith("_")} for r in records]}))
    if a.fls:
        for r in records:
            star = "" if not r["deleted"] else "* (deleted)"
            dt = f" [{r['date']}]" if r.get("date") else ""
            print(f"  #{r['num']} @{r['off']} {'dir' if r['is_dir'] else 'file'} {r['path']} size={r['size']}{dt} {star}")
    if a.fcat:
        if not fs.startswith("FAT") and fs != "exFAT":
            print("fcat: only FAT/exFAT images (use --icat/--rec for NTFS)"); return
        hit = next((x for x in records if x["path"] == a.fcat), None)
        if not hit or hit["is_dir"]:
            print("fcat: no such file"); return
        with open(a.image, "rb") as f:
            data = f.read()
        fn = exfat_extract if fs == "exFAT" else fat_extract
        blob = fn(data, hit["_boot"], hit["_rec"])
        if not blob:
            print("fcat: empty/unreadable"); return
        op = os.path.join(a.outdir, "fcat_" + "".join(
            c if c not in '<>:"/\\|?*' else "_" for c in hit["path"].replace("/", "_").strip("_")))
        open(op, "wb").write(blob[:hit["size"]] if len(blob) > hit["size"] else blob)
        print(f"fcat {hit['path']}: wrote {op} sha={sha256_of(open(op, 'rb').read())[:16]}")
        return
    target = None
    if a.rec is not None:
        target = next((x["_rec"] for x in records if x["num"] == a.rec and fs == "NTFS"), None)
        if not target:
            print(f"rec: no NTFS record #{a.rec}"); return
        target = dict(target); target["num"] = a.rec
    elif a.icat is not None:
        rd = ImgReader(a.image)
        buf = rd.readat(a.icat, 1024)
        rd.close()
        target = parse_mft_record(buf, 0)
        if target:
            target["off"], target["num"] = a.icat, -1
        else:
            print("icat: no FILE record at that offset"); return
    if target is not None:
        rd = ImgReader(a.image)
        op = os.path.join(a.outdir, f"extract_{target['num']}.bin")
        blob, kind = extract_record(rd, target, boot, op)
        rd.close()
        print(f"extract #{target['num']}: {kind} size={target['data_size']} runs={target['data_runs']}")
        if blob is not None:
            print(f"  wrote {op} sha={sha256_of(blob) if isinstance(blob, bytes) else blob[:16]}")

if __name__ == "__main__":
    import multiprocessing as _mp
    _mp.freeze_support()  # needed for worker processes in the PyInstaller build
    main()
