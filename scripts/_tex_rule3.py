# -*- coding: utf-8 -*-
"""GUID 去横线后的路径形式穷举"""
import csv, sqlite3, struct, sys, collections, re, itertools
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
M32 = 0xFFFFFFFF
MC = r"D:\ReverseKit\projects\apk_yyslscn\FINAL\05_INDEX\materials.csv"
DBS = {
    "new": r"D:\ReverseKit\projects\apk_yyslscn\mpkdb\Patch.new.mpkdb",
    "old": r"D:\ReverseKit\projects\apk_yyslscn\mpkdb\Patch.mpkdb",
}


def rotl32(x, r):
    x &= M32
    return ((x << r) | (x >> (32 - r))) & M32


def murmur3(data, seed=0, block_const=0xFADDAF14, fmix=True):
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
    if fmix:
        h1 ^= h1 >> 16
        h1 = (h1 * 0x85EBCA6B) & M32
        h1 ^= h1 >> 13
        h1 = (h1 * 0xC2B2AE35) & M32
        h1 ^= h1 >> 16
    return h1 & M32


guids = []
with open(MC, newline="", encoding="utf-8", errors="replace") as f:
    for r in csv.DictReader(f):
        for m in re.finditer(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", r.get("textures") or ""):
            g = m.group(1)
            if g != "00000000-0000-0000-0000-000000000000":
                guids.append(g)
guids = list(dict.fromkeys(guids))
print("guids", len(guids), guids[:2])

# 支持多种 GUID 文本形态
def variants(g):
    h = g.replace("-", "")
    up = h.upper()
    return {
        "h": h, "H": up,
        "dash": g, "DASH": g.upper(),
    }


paths_by_form = collections.defaultdict(list)
labels = list(variants(guids[0]).keys())
TEMPLATES = [
    lambda h: f"{h}.4",
    lambda h: f"{h[:2]}/{h}.4",
    lambda h: f"{h[:2]}/{h}",
    lambda h: f"{h}.1",
    lambda h: f"{h}/",
    lambda h: f"{h}.dds",
    lambda h: f"{h}.png",
    lambda h: f"tex/{h}.4",
    lambda h: f"Texture/{h}.4",
    lambda h: f"Assets/{h}.4",
]
for g in guids:
    v = variants(g)
    for lbl in labels:
        h = v[lbl]
        for ti, tf in enumerate(TEMPLATES):
            paths_by_form[f"{lbl}|t{ti}"].append(tf(h))

for dbname, db in DBS.items():
    con = sqlite3.connect(db)
    cur = con.cursor()
    table = {}
    for v0, v1, v2, v6 in cur.execute("SELECT v0,v1,v2,v6 FROM info0"):
        try:
            v0 = int(v0)
        except Exception:
            continue
        table.setdefault((v0 >> 32) & M32, (int(v1), int(v2), int(v6)))
    print(f"\n=== db {dbname} rows {len(table)} ===")
    best = []
    for form, plist in paths_by_form.items():
        for cname, cst in [("netease", 0xFADDAF14), ("std", 0xE6546B64)]:
            for fmix in (True, False):
                hit = 0
                for p in plist:
                    if murmur3(p.encode("utf-8"), 0, cst, fmix) in table:
                        hit += 1
                if hit:
                    best.append((hit, form, cname, fmix))
    best.sort(reverse=True)
    for b in best[:10]:
        print(f"  hit {b[0]}/{len(plist)}  {b[1]}  const={b[2]} fmix={b[3]}")
    if not best:
        print("  no hit at all")
