import os, sys, shutil
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pycarve
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# carve + resume parity on the toy image
shutil.rmtree(os.path.join(W, "recovered_t"), ignore_errors=True)
res, total, audit = pycarve.carve("test.img", os.path.join(W, "recovered_t"))
assert os.path.exists(os.path.join(W, "recovered_t", "hits.json"))
res2, _, _ = pycarve.carve("test.img", os.path.join(W, "recovered_t"), resume=True)
assert [(f[0], f[3]) for f in res] == [(f[0], f[3]) for f in res2], "resume diverged"
hb = open(os.path.join(W, "recovered_t", "progress.txt")).read()
assert "scan skipped (resume)" in hb
print("resume checkpoint: GREEN")

# pdf trailing-newline absorption
import struct
pdf = b"%PDF-1.4\n" + b"1 0 obj\n<< /Type /Page /Contents 2 0 R >>\nendobj\n" * 3 + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
img = bytes(4096) + pdf + bytes(4096)
p = os.path.join(W, "_pdfnl.img")
open(p, "wb").write(img)
shutil.rmtree(os.path.join(W, "_pdfnl_out"), ignore_errors=True)
res3, _, _ = pycarve.carve(p, os.path.join(W, "_pdfnl_out"))
sizes = {f[3]: f[5] for f in res3}
assert sizes.get("pdf") == len(pdf), f"pdf {sizes.get('pdf')} != {len(pdf)}"
print("pdf trailing-newline: GREEN (carved exact", len(pdf), "bytes)")
os.remove(p)
shutil.rmtree(os.path.join(W, "_pdfnl_out"), ignore_errors=True)
shutil.rmtree(os.path.join(W, "recovered_t"), ignore_errors=True)
print("ALL PARITY TESTS GREEN")
