import os, sys, subprocess, shutil
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# bad paths must print friendly guidance, never a traceback (drive UX bug class)
for bad in ("Z:\\definitely-not-here.img", "\\\\.\\Z:"):
    p = subprocess.run([sys.executable, "surrect.py", bad, "-o", os.path.join(W, "_badpath_out")],
                       capture_output=True, text=True, cwd=W)
    out = p.stdout + p.stderr
    assert "Traceback" not in out, out
    assert "cannot open" in out, out
    print("friendly error OK:", bad.split("\\")[-1])

# a folder is not a source: plain redirect guidance, no traceback
p = subprocess.run([sys.executable, "surrect.py", W, "-o", os.path.join(W, "_badpath_out2")],
                   capture_output=True, text=True, cwd=W)
out = p.stdout + p.stderr
assert "Traceback" not in out, out
assert "is a folder" in out, out
print("folder redirect OK")

# empty outdir falls back to ./recovered instead of crashing
shutil.rmtree(os.path.join(W, "recovered"), ignore_errors=True)
p = subprocess.run([sys.executable, "surrect.py", "test.img", "-o", "", "--fls"],
                   capture_output=True, text=True, cwd=W)
assert "Traceback" not in (p.stdout + p.stderr), p.stdout + p.stderr
assert os.path.exists(os.path.join(W, "recovered", "manifest.csv"))
print("empty-outdir fallback OK")
shutil.rmtree(os.path.join(W, "_badpath_out"), ignore_errors=True)
shutil.rmtree(os.path.join(W, "_badpath_out2"), ignore_errors=True)
shutil.rmtree(os.path.join(W, "recovered"), ignore_errors=True)
print("BAD-PATH TESTS GREEN")
