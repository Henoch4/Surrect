#!/usr/bin/env python3
"""Build synthetic HFS+ image: volume header + 3-node catalog (root, docs dir,
photo file with thread records) + file content. Ground truth returned."""
import struct, os

W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(W, "hfs_test.img")
BS, NB = 4096, 20
NS = 4096  # catalog node size

def key(parent, name):
    nb = name.encode("utf-16-be")
    k = struct.pack(">H", 4 + 2 + len(nb)) + struct.pack(">I", parent)
    k += struct.pack(">H", len(name)) + nb
    return k

def thread_rectype(folder):
    return 3 if folder else 4

def thread_body(is_folder_thread, parent, name):
    nb = name.encode("utf-16-be")
    return struct.pack(">HHI", thread_rectype(is_folder_thread), 0, parent) + \
        struct.pack(">H", len(name)) + nb

def folder_body(fid):
    b = bytearray(88)
    struct.pack_into(">H", b, 0, 1)
    struct.pack_into(">I", b, 8, fid)
    return bytes(b)

def file_body(fid, size, start_block, nblocks):
    b = bytearray(248)
    struct.pack_into(">H", b, 0, 2)
    struct.pack_into(">I", b, 8, fid)
    struct.pack_into(">Q", b, 88, size)
    struct.pack_into(">I", b, 88 + 12, 1)  # totalBlocks
    struct.pack_into(">I", b, 88 + 16, start_block)
    struct.pack_into(">I", b, 88 + 20, nblocks)
    return bytes(b)

def node(kind, height, records, flink=0, blink=0):
    body, offs = bytearray(), []
    for key_b, payload in records:
        rec = key_b + payload
        if len(rec) & 1:
            rec += b"\x00"
        offs.append(14 + len(body))
        body += rec
    offs.append(14 + len(body))
    nd = bytearray(NS)
    struct.pack_into(">IIBBH", nd, 0, flink, blink, kind, height, len(records))
    nd[14:14+len(body)] = body
    for i, o in enumerate(offs):
        struct.pack_into(">H", nd, NS - 2 * (i + 1), o)
    return bytes(nd)

def header_node():
    nd = bytearray(NS)
    struct.pack_into(">IIBBH", nd, 0, 0, 0, 1, 0, 0)
    struct.pack_into(">HIIII", nd, 14, 2, 1, 5, 2, 2)  # depth,root,leafRecs,first,last
    struct.pack_into(">HHII", nd, 14 + 18, NS, 256, 3, 0)  # nodeSize,...total,free
    return bytes(nd)

PAYLOAD = b"HFS-PLUS-PHOTO-DATA!" * 200  # 4200 bytes

img = bytearray(NB * BS)
o = 1024  # volume header
img[o:o+2] = b"\x48\x2b"
struct.pack_into(">H", img, o + 2, 4)
struct.pack_into(">I", img, o + 0x28, BS)
struct.pack_into(">I", img, o + 0x2C, NB)
struct.pack_into(">I", img, o + 0x44, 42)
co = o + 0x110  # catalog fork
struct.pack_into(">Q", img, co, 3 * NS)
struct.pack_into(">I", img, co + 12, 3)
struct.pack_into(">I", img, co + 16, 10)
struct.pack_into(">I", img, co + 20, 3)

n0 = header_node()
n1 = node(0, 2, [(key(2, "docs"), struct.pack(">I", 2))])  # index root -> leaf 2
leaf_recs = [
    (key(2, ""), thread_body(True, 1, "")),
    (key(2, "docs"), folder_body(16)),
    (key(16, ""), thread_body(True, 2, "docs")),
    (key(16, "photo"), file_body(17, len(PAYLOAD), 13, 2)),
    (key(17, ""), thread_body(False, 16, "photo")),
]
n2 = node(0xFF, 1, leaf_recs)
img[10*BS:10*BS+NS] = n0
img[11*BS:11*BS+NS] = n1
img[12*BS:12*BS+NS] = n2
img[13*BS:13*BS+len(PAYLOAD)] = PAYLOAD
open(IMG, "wb").write(bytes(img))
print("hfs_test.img", len(img), "payload", len(PAYLOAD))
