import os, sys, subprocess, shutil
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(W, "surrect-desktop", "src-tauri", "binaries")
TRIPLE = "x86_64-pc-windows-msvc"

def sidecar(name):
    for cand in (os.path.join(BIN, f"{name}-{TRIPLE}.exe"), os.path.join(BIN, f"{name}.exe")):
        if os.path.exists(cand):
            return cand
    return None

def run(binpath, *args, cwd=None):
    env = dict(os.environ)
    # sidecars find libewf.dll/zlib.dll beside themselves; also cover PATH just in case
    env["PATH"] = BIN + os.pathsep + env.get("PATH", "")
    p = subprocess.run([binpath, *args], capture_output=True, text=True, cwd=cwd or W, env=env)
    return p.returncode, p.stdout + p.stderr

ev = sidecar("ewfverify")
ex = sidecar("ewfexport")
ac = sidecar("ewfacquire")
if not ev or not ex:
    print("E01 sidecars absent from binaries/ — skipping (documented manual step)")
    sys.exit(0)

work = os.path.join(W, "_e01t")
shutil.rmtree(work, ignore_errors=True)
os.makedirs(work)
# sector-aligned fixture (E01 stores whole 512B sectors — ragged tails get cut)
raw = bytes(range(256)) * 64  # 16KB of16 identical 1KB? no: 256*64 = 16384 = 32 sectors
open(os.path.join(work, "src.img"), "wb").write(raw)
env = dict(os.environ)
env["PATH"] = BIN + os.pathsep + env.get("PATH", "")

def runb(name, *args):
    b = sidecar(name)
    p = subprocess.run([b, *args], capture_output=True, text=True, cwd=work, env=env)
    return p.returncode, p.stdout + p.stderr

if ac:
    rc, out = runb("ewfacquire", "-t", "ev", "-f", "encase6", "-d", "sha1", "-u", "-q",
                   "-C", "T", "-D", "t", "-e", "t", "-E", "1", "-N", "t", "src.img")
    assert rc == 0 and os.path.exists(os.path.join(work, "ev.E01")), out
    print("ewfacquire: E01 written")
else:
    print("ewfacquire not staged — need a pre-made ev.E01 in _e01t to continue")
    sys.exit(0)

rc, out = runb("ewfverify", "ev.E01")
assert rc == 0 and "SUCCESS" in out, out
print("ewfverify: SUCCESS (stored == calculated hashes)")
assert "MD5 hash stored in file" in out and "SHA1 hash stored in file" in out

rc, out = runb("ewfexport", "-f", "raw", "-t", "out", "-S", "0", "-o", "0", "-u", "-q", "ev.E01")
assert rc == 0 and os.path.exists(os.path.join(work, "out.raw")), out
got = open(os.path.join(work, "out.raw"), "rb").read()
assert got == raw, f"{len(got)} != {len(raw)}"
print(f"ewfexport round-trip: GREEN ({len(got)} bytes byte-identical)")
shutil.rmtree(work, ignore_errors=True)
print("ALL E01 TESTS GREEN")
