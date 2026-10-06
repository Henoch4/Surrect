import os, sys, hashlib, subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import surrect
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

IMG = os.path.join(W, "ext4_test.img")
assert os.path.exists(IMG), "run tests/make_ext4_img.py first"

LIVE = b"EXT4-LIVE-DATA-" * 340
GONE = b"EXT4-DELETED-SECRET!" * 100
NOTE = b"subdir-note-0123456789" * 5

# 1. listing: paths, deleted flags, subdir descent, slack name, orphan
p = subprocess.run([sys.executable, "surrect.py", IMG, "--fls-json"], capture_output=True, text=True, cwd=W)
assert p.returncode == 0, p.stderr
import json
line = next(l for l in p.stdout.splitlines() if l.startswith("{"))
j = json.loads(line)
assert j["fs"] == "ext4", j["fs"]
paths = {r["path"]: r for r in j["records"]}
for want in ("/data.bin", "/gone.txt (name only)", "/sub", "/sub/note.txt", "/orphan-ino-4"):
    assert want in paths, f"missing {want}: {sorted(paths)}"
assert paths["/gone.txt (name only)"]["deleted"] and paths["/orphan-ino-4"]["deleted"]
assert not paths["/data.bin"]["deleted"] and paths["/sub"]["is_dir"]
print("ext4 listing: GREEN (live + deleted name + subdir + orphan)")

# 2. extraction byte-proofs (multi-extent reassembly included)
for path, expect in (("/data.bin", LIVE), ("/sub/note.txt", NOTE), ("/orphan-ino-4", GONE)):
    p = subprocess.run([sys.executable, "surrect.py", IMG, "--fcat", path, "-o", os.path.join(W, "recovered_ext4t")],
                       capture_output=True, text=True, cwd=W)
    assert p.returncode == 0, p.stderr
    fn = "fcat_" + "".join(c if c not in '<>:"/\\|?*' else "_" for c in path.replace("/", "_").strip("_"))
    got = open(os.path.join(W, "recovered_ext4t", fn), "rb").read()
    assert got == expect, f"{path}: {len(got)} != {len(expect)}"
    print(f"ext4 fcat {path}: GREEN ({len(got)} bytes byte-identical)")

import shutil
shutil.rmtree(os.path.join(W, "recovered_ext4t"), ignore_errors=True)
shutil.rmtree(os.path.join(W, "recovered_ext4"), ignore_errors=True)
shutil.rmtree(os.path.join(W, "recovered"), ignore_errors=True)
print("ALL EXT4 TESTS GREEN")
