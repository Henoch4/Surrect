#!/usr/bin/env python3
"""Build sparse 1TB gauntlet image + groundtruth.json (deterministic seed).
Reproduces the Phase-4 gauntlet: 160 contiguous files (10 past 900GB),
20 fragmented MP4s (box-boundary splits, 1-16MB zero gaps), 20 decoys.
Needs NTFS (FSCTL_SET_SPARSE). ~20MB on disk, 1TB logical."""
import os, struct, random, json, hashlib, zlib, io, zipfile, sqlite3

W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(W, "gauntlet.img")
GT = os.path.join(W, "groundtruth.json")
SIZE = 1 << 40  # 1TB sparse
R = random.Random(20261003)

def mk_sparse(path, size):
    import msvcrt, ctypes
    if os.path.exists(path):
        os.remove(path)
    f = open(path, "w+b")
    h = msvcrt.get_osfhandle(f.fileno())
    out = ctypes.c_ulong(0)
    rc = ctypes.windll.kernel32.DeviceIoControl(h, 0x900C4, None, 0, None, 0, ctypes.byref(out), None)
    assert rc, "FSCTL_SET_SPARSE failed (needs NTFS)"
    f.seek(size - 1)
    f.write(b"\x00")
    f.flush()
    return f

def png_bytes(w=8, h=8):
    import binascii
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + bytes(R.randrange(256) for _ in range(w * 3)) for _ in range(h))
    comp = zlib.compress(raw)
    def ck(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", binascii.crc32(t + d) & 0xFFFFFFFF)
    return bytes.fromhex("89504e470d0a1a0a") + ck(b"IHDR", ihdr) + ck(b"IDAT", comp) + ck(b"IEND", b"")

def bmp_bytes(w=32, h=32):
    row = ((24 * w + 31) // 32) * 4
    pix = bytes(R.randrange(256) for _ in range(row * h))
    fsize = 14 + 40 + len(pix)
    return struct.pack("<2sIHHI", b"BM", fsize, 0, 0, 54) + \
        struct.pack("<IIIHHIIIIII", 40, w, h, 1, 24, 0, len(pix), 0, 0, 0, 0) + pix

def gif_bytes():
    return b"GIF89a" + struct.pack("<HHHH", 8, 8, 0, 0) + b"\x00" * 16 + b"\x00\x3b"

def pdf_bytes(n):
    body = b"%PDF-1.4\n" + b"".join(
        b"%d 0 obj\n<< /Type /Page >>\nendobj\n" % i for i in range(1, n + 1))
    return body + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"

def jpg_bytes():
    return bytes.fromhex("ffd8ffe000104a4649460001") + bytes(R.randrange(256) for _ in range(512)) + \
        bytes.fromhex("ffda") + bytes(R.randrange(256) for _ in range(1024)) + bytes.fromhex("ffd9")

def mp4_bytes(nbox=4):
    # ftyp: size(4)+type(4)+major(4)+minor+compat(20) = 32 total — box-exact
    out = struct.pack(">I4s", 32, b"ftyp") + b"isom" + bytes(20)
    out += struct.pack(">I4s", 64, b"moov") + bytes(56)
    for _ in range(nbox):
        sz = R.randrange(4096, 65536)
        out += struct.pack(">I4s", sz + 8, b"mdat") + bytes(R.randrange(256) for _ in range(sz))
    return out

def zip_bytes(nfiles=3):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(nfiles):
            z.writestr(f"file{i}.bin", R.randbytes(R.randrange(512, 8192)),
                       compress_type=zipfile.ZIP_STORED if i % 2 else zipfile.ZIP_DEFLATED)
    return buf.getvalue()

def mp3_bytes():
    return b"ID3\x04\x00" + b"\x00" * 4 + bytes(R.randrange(256) for _ in range(4096))

def sqlite_bytes():
    p = os.path.join(W, "_g.db")
    if os.path.exists(p):
        os.remove(p)
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE t(a BLOB)")
    c.executemany("INSERT INTO t VALUES (?)", [(R.randbytes(200),)] * 20)
    c.commit(); c.close()
    b = open(p, "rb").read()
    os.remove(p)
    return b

def wav_bytes(sec=1):
    n = 44100 * sec * 2
    data = bytes(R.randrange(256) for _ in range(n))
    return b"RIFF" + struct.pack("<I", 36 + n) + b"WAVEfmt " + struct.pack("<I", 16) + \
        struct.pack("<HHIIHH", 1, 1, 44100, 88200, 2, 16) + b"data" + struct.pack("<I", n) + data

def ico_bytes():
    px = bytes(R.randrange(256) for _ in range(16 * 16 * 4))
    dib = struct.pack("<IiiHHIIiiII", 40, 16, 32, 1, 32, 0, len(px), 0, 0, 0, 0)
    return struct.pack("<HHH", 0, 1, 1) + \
        struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, len(dib) + len(px), 22) + dib + px

MAKERS = [("png", png_bytes), ("bmp", bmp_bytes), ("gif", gif_bytes),
          ("pdf", lambda: pdf_bytes(3)), ("jpg", jpg_bytes), ("mp4", mp4_bytes),
          ("zip", zip_bytes), ("mp3", mp3_bytes), ("sqlite", sqlite_bytes),
          ("wav", lambda: wav_bytes(1)), ("ico", ico_bytes)]

f = mk_sparse(IMG, SIZE)
gt, used = [], []

def place(payload):
    for _ in range(200):
        off = R.randrange(0, SIZE - len(payload) - (1 << 20))
        if all(abs(off - u[0]) > u[1] + (1 << 20) for u in used):
            break
    else:
        raise RuntimeError("placement failed")
    f.seek(off)
    f.write(payload)
    used.append((off, len(payload)))
    return off

ext_of = {"png": "png", "bmp": "bmp", "gif": "gif", "pdf": "pdf", "jpg": "jpg",
          "mp4": "mp4", "zip": "zip", "mp3": "mp3", "sqlite": "sqlite", "wav": "wav", "ico": "ico"}

# 160 contiguous files (10 high >900GB for 64-bit proof)
for i in range(160):
    kind, mk = MAKERS[i % len(MAKERS)]
    if i >= 150:
        payload = mk()
        off = 950 * (1 << 30) + i * (1 << 20)
        f.seek(off)
        f.write(payload)
        used.append((off, len(payload)))
    else:
        payload = mk()
        off = place(payload)
    gt.append({"off": off, "size": len(payload),
               "sha": hashlib.sha256(payload).hexdigest(), "ext": ext_of[kind], "frags": None})

# 20 fragmented mp4 (split at top-level box boundary + random zero gap)
for i in range(20):
    payload = mp4_bytes(R.randrange(3, 6))
    bounds, j = [0], 0
    while j + 8 <= len(payload):
        sz = struct.unpack_from(">I", payload, j)[0]
        if sz < 8 or j + sz > len(payload):
            break
        j += sz
        bounds.append(j)
    past = [x for x in bounds if x > len(payload) // 4 and x < len(payload) - 64]
    j = R.choice(past) if past else len(payload) // 2
    a, b = payload[:j], payload[j:]
    gap = R.randrange(1 << 20, 16 << 20)
    o1 = place(a)
    used[-1] = (o1, len(a) + gap + len(b))
    o2 = o1 + len(a) + gap
    f.seek(o2)
    f.write(b)
    gt.append({"off": o1, "size": len(payload), "sha": hashlib.sha256(payload).hexdigest(),
               "ext": "mp4", "frags": [[o1, len(a)], [o2, len(b)]]})

# 20 decoys (must NOT be carved)
for i in range(20):
    junk = b"\xff\xd8\xff" + os.urandom(200)
    if i % 2:
        junk = bytes.fromhex("89504e470d0a1a0a") + b"BAD!" + os.urandom(100)
    off = place(junk)
    gt.append({"off": off, "size": len(junk), "sha": hashlib.sha256(junk).hexdigest(),
               "ext": "DECOY", "frags": None})

f.close()
json.dump(gt, open(GT, "w"))
print("gauntlet files:", len(gt))
print("BUILT", IMG)
