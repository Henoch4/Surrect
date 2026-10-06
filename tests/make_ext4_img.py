#!/usr/bin/env python3
"""Build synthetic ext4 image: root + live multi-extent file + deleted file +
deleted dir entry (standard zeroed-inode) + subdir. Ground truth returned."""
import struct, os

W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(W, "ext4_test.img")
BS = 4096

def dirent(ino, name, rec_len=None, ftype=1):
    nb = name.encode()
    ideal = 8 + ((len(nb) + 3) & ~3)
    rl = rec_len or ideal
    e = bytearray(rl)
    struct.pack_into("<I", e, 0, ino)
    struct.pack_into("<H", e, 4, rl)
    e[6], e[7] = len(nb), ftype
    e[8:8+len(nb)] = nb
    return bytes(e)

def extent_block(entries):
    """entries: [(logical, length, phys)] -> extent-tree block bytes (depth 0)."""
    b = bytearray(12 + 12 * len(entries))
    struct.pack_into("<HHHHI", b, 0, 0xF30A, len(entries), 4, 0, 0)
    for k, (ln, ln_len, phys) in enumerate(entries):
        struct.pack_into("<IHHI", b, 12 + k * 12, ln, ln_len, 0, phys)
    return bytes(b)

def inode(mode, size, links, dtime, extents):
    r = bytearray(256)
    struct.pack_into("<H", r, 0, mode)
    struct.pack_into("<I", r, 4, size & 0xFFFFFFFF)
    struct.pack_into("<I", r, 20, dtime)
    struct.pack_into("<H", r, 26, links)
    struct.pack_into("<I", r, 32, 0x80000)
    r[40:40+len(extents)] = extents
    struct.pack_into("<I", r, 108, (size >> 32) & 0xFFFFFFFF)
    return bytes(r)

img = bytearray(11 * BS)
# superblock @1024
o = 1024
struct.pack_into("<I", img, o + 0x14, 0)        # first_data_block
struct.pack_into("<I", img, o + 0x18, 2)        # log_bs -> 4096
struct.pack_into("<I", img, o + 0x20, 11)       # blocks/group
struct.pack_into("<I", img, o + 0x28, 8)        # inodes/group
struct.pack_into("<H", img, o + 0x58, 256)      # inode size
struct.pack_into("<I", img, o + 0x60, 0x42)    # incompat: FILETYPE|EXTENTS
struct.pack_into("<H", img, o + 0xFE, 32)       # desc size
img[1024+0x38:1024+0x3A] = b"\x53\xef"
# group descriptor @block 1: bitmaps + inode table
struct.pack_into("<III", img, BS, 2, 3, 4)
# block bitmap block 2: blocks 0-10 used
img[2*BS] = 0xFF
img[2*BS+1] = 0x07
# inode bitmap block 3: inodes 2,3,4,5,6 used (bits 1..5)
img[3*BS] = 0x3E
# inode table @block 4 (8 x 256B)
LIVE = b"EXT4-LIVE-DATA-" * 340          # 5440 bytes, 2 extents
GONE = b"EXT4-DELETED-SECRET!" * 100     # 2000 bytes
NOTE = b"subdir-note-0123456789" * 5     # 110 bytes
img[4*BS + 1*256:4*BS + 2*256] = inode(0x41ED, BS, 4, 0, extent_block([(0, 1, 5)]))
img[4*BS + 2*256:4*BS + 3*256] = inode(0x81A4, len(LIVE), 1, 0, extent_block([(0, 1, 6), (1, 1, 8)]))
img[4*BS + 3*256:4*BS + 4*256] = inode(0x81A4, len(GONE), 0, 1234567890, extent_block([(0, 1, 7)]))
img[4*BS + 4*256:4*BS + 5*256] = inode(0x41ED, BS, 3, 0, extent_block([(0, 1, 9)]))
img[4*BS + 5*256:4*BS + 6*256] = inode(0x81A4, len(NOTE), 1, 0, extent_block([(0, 1, 10)]))
# root dir @block 5: dead 'gone.txt' entry carries 48B slack
root = bytearray()
root += dirent(2, ".", 12, 2) + dirent(2, "..", 12, 2) + dirent(3, "data.bin", 16)
root += dirent(0, "gone.txt", 64)
root += dirent(5, "sub", BS - len(root))
img[5*BS:5*BS+len(root)] = root
# subdir @block 9
sub = dirent(5, ".", 12, 2) + dirent(2, "..", 12, 2) + dirent(6, "note.txt", BS - 24)
img[9*BS:9*BS+len(sub)] = sub
# file data
img[6*BS:6*BS+BS] = LIVE[:BS]
img[8*BS:8*BS+len(LIVE)-BS] = LIVE[BS:]
img[7*BS:7*BS+len(GONE)] = GONE
img[10*BS:10*BS+len(NOTE)] = NOTE
open(IMG, "wb").write(bytes(img))
print("ext4_test.img", len(img), "live", len(LIVE), "gone", len(GONE), "note", len(NOTE))
