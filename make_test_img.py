#!/usr/bin/env python3
"""make_test_img - build synthetic disk image with known carvable files + fake MFT records."""
import os, base64, random, struct
random.seed(42)
OUT = r"C:\Users\Henoch\Documents\Programming Folder\file-recovery-study\test.img"

# 1x1 PNG (valid, with IEND)
png_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
png = base64.b64decode(png_b64)
jpg = bytes.fromhex("ffd8ffe000104a4649460001") + b"\x00"*200 + bytes.fromhex("ffda") + b"\x11"*200 + bytes.fromhex("ffd9")
pdf = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
gif = b"GIF89a" + b"\x01\x00\x01\x00\x00\x00\x00" + b"\x00\x3b"
# fake MFT: one in-use, one deleted (flags@22)
def mft(flags):
    r = bytearray(1024)
    r[0:4] = b"FILE"
    struct.pack_into("<H", r, 20, 48)   # attrs_offset
    struct.pack_into("<H", r, 22, flags) # flags
    return bytes(r)

blob = bytearray()
blob += os.urandom(4096)
blob += jpg; blob += os.urandom(1024)
blob += png; blob += os.urandom(1024)
blob += pdf + pdf  # two EOFs to test REVERSE
blob += os.urandom(1024)
blob += gif; blob += os.urandom(2048)
blob += mft(0x01)  # in-use
blob += os.urandom(512)
blob += mft(0x00)  # deleted
blob += os.urandom(4096)
with open(OUT, "wb") as f:
    f.write(blob)
print(f"wrote {OUT} {len(blob)} bytes: jpg={len(jpg)} png={len(png)} pdf={len(pdf)} gif={len(gif)}")
