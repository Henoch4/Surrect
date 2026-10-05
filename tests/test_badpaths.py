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
shutil.rmtree(os.path.join(W, "_badpath_out"), ignore_errors=True)
print("BAD-PATH TESTS GREEN")
