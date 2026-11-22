# -*- coding: utf-8 -*-
"""验证贴图定位规则：GUID→路径→murmur→mpkdb"""
import csv, os, sqlite3, struct, sys, collections, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

M32 = 0xFFFFFFFF
MC = r"D:\ReverseKit\projects\apk_yyslscn\FINAL\05_INDEX\materials.csv"
DB = r"D:\ReverseKit\projects\apk_yyslscn\mpkdb\Patch.new.mpkdb"


def rotl32(x, r):
    x &= M32
    return ((x << r) | (x >> (32 - r))) & M32


def murmur3(data, seed=0, block_const=0xFADDAF14):
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


guids = []
with open(MC, newline="", encoding="utf-8", errors="replace") as f:
    for r in csv.DictReader(f):
        t = r.get("textures") or ""
        for m in re.finditer(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", t):
            g = m.group(1)
            if g != "00000000-0000-0000-0000-000000000000":
                guids.append(g)
guids = list(dict.fromkeys(guids))
print("unique texture GUIDs:", len(guids))

con = sqlite3.connect(DB)
cur = con.cursor()
table = {}
for v0, v1, v2, v6 in cur.execute("SELECT v0,v1,v2,v6 FROM info0"):
    try:
        v0 = int(v0)
    except Exception:
        continue
    table.setdefault((v0 >> 32) & M32, (int(v1), int(v2), int(v6)))
print("index rows", len(table))

forms = ["{g}/{g}", "{g}", "tex/{g}", "{g}/{g}.4", "{g}.4"]
consts = [("netease", 0xFADDAF14), ("std", 0xE6546B64)]
for cname, cst in consts:
    for fmt in forms:
        hit = 0
        packs = collections.Counter()
        for g in guids[:600]:
            p = fmt.format(g=g)
            h = murmur3(p.encode("utf-8"), 0, cst)
            r = table.get(h)
            if r:
                hit += 1
                packs[r[1]] += 1
        print(f"{cname:8} {fmt:14} hit {hit}/{min(600,len(guids))}  packs {packs.most_common(5)}")
