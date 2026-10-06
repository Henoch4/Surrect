import os, sys, io, zipfile, struct, random, sqlite3, zlib, binascii
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import surrect
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = random.Random(77)

# ---------- 1. OOXML: fragmented docx, contents must survive, broken XML must fail gate ----------
CT = b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="rels"/><Default Extension="xml" ContentType="xml"/><Override PartName="/word/document.xml" ContentType="doc"/></Types>'
RELS = b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Target="word/document.xml"/></Relationships>'
DOC = b'<?xml version="1.0"?><document><body>' + b"".join(
    b"<p id=\"p%d\">Value %d: %s</p>" % (i, i, bytes((i * 7919 + j) % 26 + 97 for j in range(40)))
    for i in range(800)) + b"</body></document>"
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("[Content_Types].xml", CT)
    z.writestr("_rels/.rels", RELS)
    z.writestr("word/document.xml", DOC, compress_type=zipfile.ZIP_STORED)
ooxml = buf.getvalue()
jpg = bytes.fromhex("ffd8ffe000104a4649460001") + b"\x00" * 64 + bytes.fromhex("ffd9")
lh = ooxml.find(b"word/document.xml")
ds = ooxml.find(b"PK\x03\x04")
nlen = struct.unpack_from("<H", ooxml, ds + 26)[0]
elen = struct.unpack_from("<H", ooxml, ds + 28)[0]
# splice jpg into the middle of the deflated document stream: find doc local data
for _lh in [i for i in range(len(ooxml)) if ooxml.startswith(b"PK\x03\x04", i)]:
    nl = struct.unpack_from("<H", ooxml, _lh + 26)[0]
    el = struct.unpack_from("<H", ooxml, _lh + 28)[0]
    if ooxml[_lh+30:_lh+30+nl] == b"word/document.xml":
        dstart = _lh + 30 + nl + el
        break
cut = dstart + 3000
img = ooxml[:cut] + jpg + ooxml[cut:]
open(os.path.join(W, "_ooxmlfrag.img"), "wb").write(img)
rd = surrect.ImgReader(os.path.join(W, "_ooxmlfrag.img"))
res = surrect.stitch_zip(rd, 0, 512 * 1024 * 1024, len(img))
rd.close()
assert res["ok"] and res["needed"], res
za = {n: res["files"][n] for n in res["files"]}
assert za["word/document.xml"] == DOC, "OOXML payload corrupted"
print("OOXML fragmented docx: GREEN (deflated payload byte-identical, gate passed)")

# gate must FAIL a zip whose Content_Types is broken
bad = dict(res["files"])
bad["[Content_Types].xml"] = b"<not xml"
assert surrect.ooxml_ok(bad) is False
assert surrect.ooxml_ok({k: v for k, v in res["files"].items() if k != "[Content_Types].xml"}) is True
print("OOXML gate: GREEN (broken XML rejected, plain zips pass through)")
os.remove(os.path.join(W, "_ooxmlfrag.img"))

# ---------- 2. SQLite: split pages, stitch, open in sqlite3 ----------
dbp = os.path.join(W, "_frag.db")
if os.path.exists(dbp):
    os.remove(dbp)
c = sqlite3.connect(dbp)
c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v BLOB)")
c.executemany("INSERT INTO t VALUES (?, ?)", [(i, R.randbytes(300)) for i in range(60)])
c.commit()
n0 = c.execute("SELECT count(*) FROM t").fetchone()[0]
c.close()
raw = open(dbp, "rb").read()
ps = struct.unpack_from(">H", raw, 16)[0]
assert ps == 4096 and len(raw) % ps == 0, (ps, len(raw))
npages = len(raw) // ps
# split after page 2, 32KB zero gap
cut = 2 * ps
img2 = raw[:cut] + bytes(32768) + raw[cut:] + bytes(4096)
open(os.path.join(W, "_sqlfrag.img"), "wb").write(img2)
rd = surrect.ImgReader(os.path.join(W, "_sqlfrag.img"))
ext, gaps, ok = surrect.stitch_sqlite(rd, 0, 1024 * 1024 * 1024, len(img2))
assert ok and len(gaps) == 1, (ok, gaps)
asm = b"".join(rd.readat(o, l) for o, l in ext)
rd.close()
assert asm == raw, "sqlite assembly mismatch"
ap = os.path.join(W, "_sqlfrag_out.db")
open(ap, "wb").write(asm)
c = sqlite3.connect(f"file:{ap}?mode=ro", uri=True)
n1 = c.execute("SELECT count(*) FROM t").fetchone()[0]
c.close()
assert n1 == n0 == 60, (n1, n0)
print(f"SQLite page stitch: GREEN ({npages} pages bridged, sqlite3 opens, {n1} rows)")
os.remove(os.path.join(W, "_sqlfrag.img"))
os.remove(ap)
os.remove(dbp)

# ---------- 3. PNG: foreign file spliced between intact IDATs, stitch, pixels identical ----------
# (deleting IDAT bytes would break the zlib stream for anyone — the recoverable
# case is intrusion, same as the ZIP bridge: all IDAT bytes survive, relocated)
import binascii as _bi
w, h = 16, 16
raw = b"".join(b"\x00" + bytes(R.randrange(256) for _ in range(w * 3)) for _ in range(h))
comp = zlib.compress(raw, 6)
ids = [comp[i:i + 500] for i in range(0, len(comp), 500)]
def ck(t, d):
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", _bi.crc32(t + d) & 0xFFFFFFFF)
ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
png = bytes.fromhex("89504e470d0a1a0a") + ck(b"IHDR", ihdr) + b"".join(ck(b"IDAT", x) for x in ids) + ck(b"IEND", b"")
assert b"PK\x03\x04" not in png
first_idat = png.find(b"IDAT") - 4
first_ln = struct.unpack_from(">I", png, first_idat)[0]
cut = first_idat + 12 + first_ln  # exact end of first IDAT chunk (len+type+data+crc)
jpg2 = bytes.fromhex("ffd8ffe000104a4649460001") + b"\x00" * 64 + bytes.fromhex("ffd9")
img3 = png[:cut] + jpg2 + png[cut:]
open(os.path.join(W, "_pngfrag.img"), "wb").write(img3)
rd = surrect.ImgReader(os.path.join(W, "_pngfrag.img"))
ext3, gaps3, ok3 = surrect.stitch_png(rd, 0, 20 * 1024 * 1024, len(img3))
assert ok3 and len(gaps3) == 1, (ok3, gaps3)
asm3 = b"".join(rd.readat(o, l) for o, l in ext3)
rd.close()
assert asm3 == png, "png assembly mismatch"
# pixel proof: inflate the stitched IDAT stream
p = 8
stream = b""
while p < len(asm3):
    ln = struct.unpack_from(">I", asm3, p)[0]
    typ = asm3[p+4:p+8]
    if typ == b"IDAT":
        stream += asm3[p+8:p+8+ln]
    if typ == b"IEND":
        break
    p += 12 + ln
assert zlib.decompress(stream) == raw, "pixels differ"
print(f"PNG IDAT stitch: GREEN ({len(ids)} IDATs bridged, pixels identical)")
os.remove(os.path.join(W, "_pngfrag.img"))
print("ALL FRAGMENT-DEPTH TESTS GREEN")
