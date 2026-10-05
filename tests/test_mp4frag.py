import os, random, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import surrect
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = random.Random(11)
SRC = open(os.path.join(W, "..", "test_download.mp4"), "rb").read()

SPLIT = 50193  # mdat box start
frag1, frag2 = SRC[:SPLIT], SRC[SPLIT:]
gap1 = os.urandom(65536)
decoy = b"\x00\x00\x10\x00ftyp" + os.urandom(4064) + os.urandom(4096)
img = frag1 + gap1
decoy_off = len(img)
img += decoy + os.urandom(32768)
frag2_off = len(img)
img = bytearray(img + frag2 + os.urandom(8192))
img2 = frag1 + bytes(12 << 20) + frag2 + bytes(8192)
open(os.path.join(W, "mp4frag_test.img"), "wb").write(bytes(img))
open(os.path.join(W, "mp4frag_zerotest.img"), "wb").write(img2)

t0 = time.time()
r = surrect.ImgReader(os.path.join(W, "mp4frag_test.img"))
ext, gaps, score, complete = surrect.stitch_mp4(r, 4, 4 * 1024 * 1024 * 1024, len(img))
asm = b"".join(r.readat(o, l) for o, l in ext)
r.close()
print(f"case1 (random gap + decoy): {time.time()-t0:.1f}s score={score} gaps={gaps}")
assert asm == SRC, "STITCH MISMATCH"
for o, l in ext:
    assert not (o <= decoy_off < o + l), "DECOY SWALLOWED"
print("case1 OK: byte-exact, decoy rejected")

t0 = time.time()
r = surrect.ImgReader(os.path.join(W, "mp4frag_zerotest.img"))
ext2, gaps2, score2, _ = surrect.stitch_mp4(r, 4, 4 * 1024 * 1024 * 1024, len(img2))
asm2 = b"".join(r.readat(o, l) for o, l in ext2)
r.close()
print(f"case2 (12MB zero gap): {time.time()-t0:.1f}s score={score2} gaps={gaps2}")
assert asm2 == SRC, "ZERO-GAP STITCH MISMATCH"
print("case2 OK: byte-exact across 12MB of zeros")

os.remove(os.path.join(W, "mp4frag_test.img"))
os.remove(os.path.join(W, "mp4frag_zerotest.img"))
print("MP4 STITCHER GREEN")
