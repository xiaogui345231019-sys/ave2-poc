# -*- coding: utf-8 -*-
"""用 texture_pairs.csv 的真实贴图路径去 Patch.mpkdb 查 pack/offset，看角色贴图落在哪些包"""
import csv, os, sqlite3, struct, sys, collections
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

M32 = 0xFFFFFFFF
IDX = r"D:\ReverseKit\projects\apk_yyslscn\FINAL\05_INDEX\texture_pairs.csv"
DB = r"D:\ReverseKit\projects\apk_yyslscn\mpkdb\Patch.new.mpkdb"


def rotl32(x, r):
    x &= M32
    return ((x << r) | (x >> (32 - r))) & M32


def murmur3_x86_32(data, seed=0, block_const=0xFADDAF14):
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


paths = set()
slots = collections.Counter()
rows = 0
with open(IDX, newline="", encoding="utf-8", errors="replace") as f:
    for r in csv.DictReader(f):
        rows += 1
        p = (r.get("texture_path") or "").strip()
        if p:
            paths.add(p)
            slots[r.get("slot", "")] += 1
print("texture_pairs rows", rows, "unique paths", len(paths))
print("slots", slots.most_common(8))

con = sqlite3.connect(DB)
cur = con.cursor()
print("loading index ...")
table = {}
for v0, v1, v2, v6 in cur.execute("SELECT v0,v1,v2,v6 FROM info0"):
    try:
        v0 = int(v0)
    except Exception:
        continue
    table.setdefault((v0 >> 32) & M32, (int(v1), int(v2), int(v6)))
print("index rows", len(table))
hit = 0
packs = collections.Counter()
no = []
for p in sorted(paths):
    h = murmur3_x86_32(p.encode("utf-8"))
    row = table.get(h)
    if row:
        hit += 1
        packs[row[1]] += 1
    else:
        no.append(p)
print(f"murmur high32 hit {hit}/{len(paths)} = {hit/len(paths)*100:.1f}%")
print("packs:", packs.most_common(15))
print("miss sample:", no[:6])
