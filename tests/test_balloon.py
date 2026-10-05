import sys, os, struct, sqlite3, shutil, random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import surrect
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# small sqlite
p = os.path.join(W, "_b.db")
if os.path.exists(p):
    os.remove(p)
c = sqlite3.connect(p)
c.execute("CREATE TABLE t(a BLOB)")
c.executemany("INSERT INTO t VALUES (?)", [(os.urandom(200),)] * 10)
c.commit(); c.close()
sq = open(p, "rb").read()
os.remove(p)

R = random.Random(1)
mp3 = b"ID3\x04\x00" + b"\x00" * 4 + R.randbytes(4096)
dib = struct.pack("<IiiHHIIiiII", 40, 16, 32, 1, 32, 0, 1024, 0, 0, 0, 0)
ico = (struct.pack("<HHH", 0, 1, 1) +
       struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, 40 + 1024, 22) + dib + R.randbytes(1024))
exe = bytearray(R.randbytes(512))
exe[0:2] = b"MZ"
struct.pack_into("<I", exe, 0x3C, 64)
exe[64:68] = b"PE\x00\x00"

img = sq + bytes(1 << 20) + mp3 + bytes(2 << 20) + ico + bytes(1 << 20) + bytes(exe) + bytes(1 << 20)
imgp = os.path.join(W, "balloon_test.img")
open(imgp, "wb").write(img)

shutil.rmtree(os.path.join(W, "recovered_balloon"), ignore_errors=True)
res, total, audit = surrect.carve(imgp, os.path.join(W, "recovered_balloon"))
sizes = {f[3]: f[5] for f in res}
print("carved:", [(f[0], f[5]) for f in res])
assert sizes.get("sqlite") == len(sq), f"sqlite {sizes.get('sqlite')} != {len(sq)}"
assert sizes.get("mp3") == len(mp3), f"mp3 {sizes.get('mp3')} != {len(mp3)}"
assert sizes.get("ico") == len(ico), f"ico {sizes.get('ico')} != {len(ico)}"
assert sizes.get("exe") == len(exe), f"exe {sizes.get('exe')} != {len(exe)}"
print("NO BALLOONS: sqlite/mp3/ico/exe all carve at true size")
os.remove(imgp)
shutil.rmtree(os.path.join(W, "recovered_balloon"), ignore_errors=True)
