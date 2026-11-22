# -*- coding: utf-8 -*-
"""APK 内 Resources.mpkinfo 定位测试：GUID → murmur → 索引 → 解容器"""
import csv, os, sqlite3, struct, sys, collections
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
M32 = 0xFFFFFFFF
ROOT = r"D:\ReverseKit\projects\apk_yyslscn"
INFO = os.path.join(ROOT, r"res1\Resources.mpkinfo")
REPO = os.path.join(ROOT, r"FINAL\05_INDEX\repository.csv")


def rotl32(x, r):
    x &= M32
    return ((x << r) | (x >> (32 - r))) & M32


def murmur3(data, seed=0, block_const=0xE6546B64):
    c1, c2 = 0xCC9E2D51, 0x1B873593
    n = len(data)
    h1 = seed & M32
    nb = n // 4
    for i in range(nb):
        k1 = struct.unpack_from("<I", data, i * 4)[0]
        k1 = (k1 * c1) & M32
        k1 = rotl32(k1, 15)
        k1 = (k1 * c2) & M32
        h1 ^= k1
        h1 = rotl32(h1, 13)
        h1 = (h1 * 5 + block_const) & M32
    tail = data[nb * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & M32
        k1 = rotl32(k1, 15)
        k1 = (k1 * c2) & M32
        h1 ^= k1
    h1 ^= n
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & M32
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & M32
    h1 ^= h1 >> 16
    return h1 & M32


raw = open(INFO, "rb").read()
N = (len(raw) - 24) // 20
hdr = struct.unpack_from("<6I", raw, 0)
print("header", hdr, "records", N)
recs = [struct.unpack_from("<5I", raw, 24 + i * 20) for i in range(N)]
print("sample recs", recs[:4])
h1set = collections.Counter(r[1] for r in recs)
h2set = collections.Counter(r[2] for r in recs)
print("hash1 uniq", len(h1set), "hash2 uniq", len(h2set))

# 目标：套装贴图名 → GUID（含 merged 图集）
targets = {}
with open(REPO, newline="", encoding="utf-8-sig", errors="replace") as f:
    for r in csv.DictReader(f):
        nm = (r.get("name") or "")
        if (r.get("type") or "") != "Texture2D":
            continue
        if "merged" in nm and ("lyxk" in nm or "hsn" in nm):
            targets[nm] = r.get("guid")
print("merged atlas candidates:", len(targets), list(targets.items())[:3])

h2map = {}
for flag, a, b, off, size in recs:
    h2map.setdefault(b, (flag, a, off, size))

for label, tmpl in [("g[:2]/g.4", lambda g: f"{g[:2]}/{g}.4"),
                    ("g.4", lambda g: f"{g}.4"),
                    ("g", lambda g: g)]:
    hit = 0
    for nm, g in targets.items():
        if not g:
            continue
        if murmur3(tmpl(g).encode()) in h2map:
            hit += 1
    print(f"{label:12} hit {hit}/{len(targets)}")
