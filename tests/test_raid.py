import os, sys, random, hashlib, struct, shutil
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import surrect
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = random.Random(99)
S = 65536

def stripe_ls(members_data, s=S):
    """Lay out logical bytes RAID5 left-symmetric across member bytearrays."""
    n = len(members_data)
    out = [bytearray(m) for m in members_data]
    return out

def build_raid5_ls(payload, s=S, n=3):
    """Stripe payload (padded) RAID5-LS into n member bytearrays + parity."""
    data_len = ((len(payload) + (n - 1) * s - 1) // ((n - 1) * s)) * (n - 1) * s
    payload = payload + bytes(data_len - len(payload))
    members = [bytearray(data_len // (n - 1)) for _ in range(n)]
    for k in range(data_len // ((n - 1) * s)):
        p = surrect.raid_parity_slot(n, k, "LS")
        row = [payload[k*(n-1)*s + d*s:k*(n-1)*s + (d+1)*s] for d in range(n - 1)]
        x = bytearray(s)
        for d in row:
            for i in range(s):
                x[i] ^= d[i]
        chunks = {}
        for d in range(n - 1):
            chunks[surrect.raid_data_slot(n, k, d, "LS")] = row[d]
        chunks[p] = bytes(x)
        for slot in range(n):
            members[slot][k*s:(k+1)*s] = chunks[slot]
    return [bytes(m) for m in members]

# NTFS-ish boot at logical 0 for detect scoring
boot = bytearray(512)
boot[0:3] = b"\xeb\x52\x90"
boot[3:11] = b"NTFS    "
boot[510:512] = b"\x55\xaa"

def fake_mft():
    r = bytearray(120)
    r[0:4] = b"FILE"
    struct.pack_into("<H", r, 16, 1)
    struct.pack_into("<H", r, 20, 48)
    struct.pack_into("<H", r, 22, 1)
    struct.pack_into("<II", r, 48, 0x80, 64)
    r[48 + 8] = 0
    struct.pack_into("<I", r, 48 + 16, 8)
    struct.pack_into("<H", r, 48 + 20, 32)
    struct.pack_into("<Q", r, 48 + 48, 8)
    r[48 + 32:48 + 40] = b"PAYLOAD!"
    struct.pack_into("<II", r, 48 + 64, 0xFFFFFFFF, 8)
    return bytes(r)

# payload with 4 MFTs SPREAD over 210KB (like a real MFT zone — one tight
# cluster would also reward sub-harmonic stripes). NOTE: extend to full
# length FIRST — slice-assign past the end appends!
payload = bytearray(bytes(boot) + R.randbytes(1024 * 1024 - 512))
while len(payload) < 1024 * 1024 + 220 * 1024:
    payload += R.randbytes(1024)
for k, gap in enumerate((0, 70 * 1024, 140 * 1024, 210 * 1024)):
    o = 1024 * 1024 + gap
    payload[o:o + 120] = fake_mft()
payload += R.randbytes(100 * 1024)
payload = bytes(payload)
members = build_raid5_ls(payload)
for i, m in enumerate(members):
    open(os.path.join(W, f"_r5m{i}.img"), "wb").write(m)

# 1. full rebuild, all members
rr = surrect.RaidReader([os.path.join(W, f"_r5m{i}.img") for i in range(3)], 5, [0, 1, 2], S, "LS")
got = rr.readat(0, len(payload))
rr.close()
assert got == payload, "RAID5 full rebuild mismatch"
print("RAID5 full rebuild: GREEN")

# 2. degraded rebuild, member 1 missing (XOR path)
rr = surrect.RaidReader([os.path.join(W, "_r5m0.img"), None, os.path.join(W, "_r5m2.img")],
                        5, [0, 1, 2], S, "LS", missing=1)
got = rr.readat(0, len(payload))
rr.close()
assert got == payload, "RAID5 degraded rebuild mismatch"
print("RAID5 degraded (1 missing): GREEN")

# 3. detect ranks truth top
det = surrect.raid_detect([os.path.join(W, f"_r5m{i}.img") for i in range(3)])
print("detect top:", det[0])
assert det[0]["stripe"] == S and det[0]["rotation"] == "LS" and det[0]["order"] == [0, 1, 2], det[0]
print("RAID5 detect: GREEN")

# 4. RAID0: 2 members, file spanning stripes
a, b = R.randbytes(100000), R.randbytes(100000)
m0 = bytearray(200000)
m1 = bytearray(200000)
# interleave (a+b) across m0/m1 in S chunks
full = a + b
for k in range((len(full) + S - 1) // S):
    (m0 if k % 2 == 0 else m1)[(k // 2) * S:(k // 2) * S + S] = full[k*S:(k+1)*S].ljust(S, b"\x00")
open(os.path.join(W, "_r0m0.img"), "wb").write(bytes(m0))
open(os.path.join(W, "_r0m1.img"), "wb").write(bytes(m1))
rr = surrect.RaidReader([os.path.join(W, "_r0m0.img"), os.path.join(W, "_r0m1.img")], 0, [0, 1], S)
assert rr.readat(0, len(full)) == full, "RAID0 mismatch"
rr.close()
print("RAID0 striped rebuild: GREEN")

# 5. RAID1: mirror, one member missing
open(os.path.join(W, "_r1m0.img"), "wb").write(a)
rr = surrect.RaidReader([os.path.join(W, "_r1m0.img"), None], 1, [0, 1], S, missing=1)
assert rr.readat(0, len(a)) == a
rr.close()
print("RAID1 mirror degraded: GREEN")

for f in ("_r5m0.img", "_r5m1.img", "_r5m2.img", "_r0m0.img", "_r0m1.img", "_r1m0.img"):
    os.remove(os.path.join(W, f))
print("ALL RAID TESTS GREEN")
