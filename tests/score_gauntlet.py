#!/usr/bin/env python3
"""Final gauntlet scorer. Classifies: TP / intermediate (raw part superseded by
its stitched whole) / FP. Writes score.json."""
import os, sys, json, csv, hashlib, time

W = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) or "."
OUT = os.path.join(W, "recovered_gaunt")
GT = json.load(open(os.path.join(W, "groundtruth.json")))
targets = [g for g in GT if g["ext"] != "DECOY"]
decoys = [g for g in GT if g["ext"] == "DECOY"]
by_sha = {}
for g in targets:
    by_sha.setdefault(g["sha"], []).append(g)

def target_bytes(g):
    with open(os.path.join(W, "gauntlet.img"), "rb") as f:
        if g["frags"]:
            b = b""
            for o, l in g["frags"]:
                f.seek(o)
                b += f.read(l)
            return b
        f.seek(g["off"])
        return f.read(g["size"])

t0 = time.time()
rows = list(csv.DictReader(open(os.path.join(OUT, "manifest.csv"))))
files = []
for row in rows:
    p = os.path.join(OUT, row["file"])
    try:
        files.append((row["file"], open(p, "rb").read()))
    except OSError:
        pass

# pass 1: TP matching (exact or prefix-of-file)
matched, used = {}, set()
for fn, b in files:
    h = hashlib.sha256(b).hexdigest()
    hit = None
    if h in by_sha:
        hit = next((g for g in by_sha[h] if id(g) not in used), None)
    if hit is None:
        for g in targets:
            if id(g) in used or len(b) < g["size"]:
                continue
            if hashlib.sha256(b[:g["size"]]).hexdigest() == g["sha"]:
                hit = g
                break
    if hit is not None:
        matched[id(hit)] = (hit, fn)
        used.add(id(hit))

# pass 2: leftovers -> intermediate (prefix of a MATCHED target) or FP
inter, fps = [], []
for fn, b in files:
    if any(m[1] == fn for m in matched.values()):
        continue
    cls = None
    for g in targets:
        if id(g) not in used or g["size"] <= len(b):
            continue
        tb = target_bytes(g)
        if tb[:len(b)] == b:
            cls = ("intermediate", fn, g["off"])
            break
    if cls:
        inter.append(cls)
        continue
    is_decoy = any(len(b) >= g["size"] and hashlib.sha256(b[:g["size"]]).hexdigest() == g["sha"] for g in decoys)
    fps.append((fn, "DECOY-CARVED" if is_decoy else "junk"))
dt = time.time() - t0

missed = [g for g in targets if id(g) not in used]
rec = len(matched) / len(targets) * 100
prec = len(matched) / max(1, (len(matched) + len(fps))) * 100
frag_targets = [g for g in targets if g["frags"]]
frag_ok = sum(1 for g in frag_targets if id(g) in used)
hi = [g for g in targets if g["off"] > 900 << 30]
hi_ok = sum(1 for g in hi if id(g) in used)

print(f"recall:      {len(matched)}/{len(targets)} = {rec:.1f}%")
print(f"precision:   {len(matched)}/{len(matched)+len(fps)} = {prec:.1f}%  (excludes {len(inter)} legitimate intermediates)")
print(f"false positives: {len(fps)} -> {[f[0] + ' ' + f[1] for f in fps[:6]]}")
print(f"missed ({len(missed)}): {[(g['ext'], g['off'], g['size']) for g in missed[:8]]}")
print(f"fragmented mp4 recovered: {frag_ok}/{len(frag_targets)}")
print(f">900GB files recovered:   {hi_ok}/{len(hi)}")
print(f"scoring took {dt:.1f}s")
json.dump({"recall": rec, "precision": prec, "matched": len(matched), "targets": len(targets),
           "fps": fps, "intermediates": len(inter),
           "missed": [(g["ext"], g["off"], g["size"]) for g in missed],
           "frag_ok": frag_ok, "frag_total": len(frag_targets),
           "hi_ok": hi_ok, "hi_total": len(hi)},
          open(os.path.join(W, "score.json"), "w"), indent=1)
print("WROTE score.json")
