import os, sys, subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import surrect
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

IMG = os.path.join(W, "hfs_test.img")
assert os.path.exists(IMG), "run tests/make_hfs_img.py first"
PAYLOAD = b"HFS-PLUS-PHOTO-DATA!" * 200

# 1. listing with thread-resolved paths
p = subprocess.run([sys.executable, "surrect.py", IMG, "--fls-json"], capture_output=True, text=True, cwd=W)
assert p.returncode == 0, p.stderr
import json
line = next(l for l in p.stdout.splitlines() if l.startswith("{"))
j = json.loads(line)
assert j["fs"] == "HFS+", j["fs"]
paths = {r["path"]: r for r in j["records"]}
assert "/docs/photo" in paths, sorted(paths)
assert "/docs" in paths and paths["/docs"]["is_dir"]
assert paths["/docs/photo"]["size"] == len(PAYLOAD)
assert not paths["/docs/photo"]["deleted"]
print("hfs listing: GREEN (thread-resolved /docs/photo + /docs)")

# 2. extraction byte-proof via fork extents
p = subprocess.run([sys.executable, "surrect.py", IMG, "--fcat", "/docs/photo", "-o", os.path.join(W, "recovered_hfst")],
                   capture_output=True, text=True, cwd=W)
assert p.returncode == 0, p.stderr
got = open(os.path.join(W, "recovered_hfst", "fcat_docs_photo"), "rb").read()
assert got == PAYLOAD, f"{len(got)} != {len(PAYLOAD)}"
print(f"hfs fcat /docs/photo: GREEN ({len(got)} bytes byte-identical)")

import shutil
shutil.rmtree(os.path.join(W, "recovered_hfst"), ignore_errors=True)
shutil.rmtree(os.path.join(W, "recovered"), ignore_errors=True)
print("ALL HFS+ TESTS GREEN")
