#!/usr/bin/env python3
"""Build synthetic NTFS image: boot + MFT (root/docs dir, deleted non-resident file, resident file)."""
import struct

BPS, SPC, CS = 512, 1, 512
MFT_LCN = 4
IMG = r"C:\Users\Henoch\Documents\Programming Folder\file-recovery-study\ntfs_test.img"
SIZE = 256 * 1024

def fname_attr(parent_num, name, is_dir=False):
    nm = name.encode("utf-16-le")
    fn = bytearray(66 + len(nm))
    struct.pack_into("<Q", fn, 0, parent_num)          # parent ref
    struct.pack_into("<QQQ", fn, 8, 0, 0, 0)           # times
    struct.pack_into("<Q", fn, 32, 0)                  # alloc size
    struct.pack_into("<Q", fn, 40, 0)                  # real size
    struct.pack_into("<I", fn, 56, 0x20 if not is_dir else 0x10000000)
    struct.pack_into("<I", fn, 60, 0)
    fn[64] = len(nm) // 2
    fn[65] = 1
    fn[66:66+len(nm)] = nm
    return bytes(fn)

def attr(atype, value, nonres=0, extra=b""):
    vlen, voff = len(value), 24
    a = bytearray(24 + vlen)
    struct.pack_into("<II", a, 0, atype, 24 + vlen)
    a[8] = nonres
    a[9] = 0
    struct.pack_into("<I", a, 16, vlen)
    struct.pack_into("<H", a, 20, voff)
    a[24:24+vlen] = value
    return bytes(a)

def attr_data_runs(runs_blob, real_size):
    a = bytearray(64)
    struct.pack_into("<II", a, 0, 0x80, 64 + len(runs_blob) + 1)
    a[8] = 1  # non-resident
    a[9] = 0
    struct.pack_into("<H", a, 32, 64)          # mapping pairs offset
    struct.pack_into("<Q", a, 40, real_size)   # allocated
    struct.pack_into("<Q", a, 48, real_size)   # real
    struct.pack_into("<Q", a, 56, real_size)   # initialized
    return bytes(a) + runs_blob + b"\x00"

def mft_rec(seq, flags, attrs):
    r = bytearray(1024)
    r[0:4] = b"FILE"
    struct.pack_into("<H", r, 16, seq)
    struct.pack_into("<H", r, 20, 48)
    struct.pack_into("<H", r, 22, flags)
    p = 48
    for a in attrs:
        r[p:p+len(a)] = a
        p += len(a)
    struct.pack_into("<II", r, p, 0xFFFFFFFF, 8)
    return bytes(r)

img = bytearray(SIZE)
# boot
img[0:3] = b"\xeb\x52\x90"
img[3:7] = b"NTFS"
struct.pack_into("<H", img, 11, BPS)
img[13] = SPC
struct.pack_into("<Q", img, 48, MFT_LCN)
img[510:512] = b"\x55\xaa"
# payload clusters: cluster 100 -> offset 51200
payload = b"NTFS-SECRET-PAYLOAD-0123456789" * 4
img[100*CS:100*CS+len(payload)] = payload
# MFT @ cluster 4
base = MFT_LCN * CS
recs = [
    mft_rec(1, 0x03, [attr(0x30, fname_attr(0, ".", True))]),                    # #0 root-ish
    mft_rec(1, 0x03, [attr(0x30, fname_attr(0, "docs", True))]),                 # #1 docs/ under #0
    mft_rec(2, 0x00, [attr(0x30, fname_attr(1, "secret.txt")),                   # #2 DELETED, non-resident
                      attr_data_runs(bytes([0x11, 0x02, 100]), len(payload))]),
    mft_rec(1, 0x01, [attr(0x30, fname_attr(1, "note.txt")),                     # #3 resident
                      attr(0x80, b"HELLO-RESIDENT")]),
]
for i, r in enumerate(recs):
    img[base+i*1024:base+(i+1)*1024] = r
with open(IMG, "wb") as f:
    f.write(img)
print(f"wrote {IMG} {SIZE} bytes, MFT@{base}, payload@{100*CS}")
