# -*- coding: utf-8 -*-
"""按 5 套套装统计：需要哪些材质贴图 → GUID → 能否在 mpkdb 定位"""
import csv, os, sqlite3, struct, sys, collections, re, glob
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

M32 = 0xFFFFFFFF
ROOT = r"D:\ReverseKit\projects\apk_yyslscn"
IDX = os.path.join(ROOT, r"FINAL\05_INDEX")
DB = os.path.join(ROOT, r"mpkdb\Patch.new.mpkdb")
SUITS = os.path.join(ROOT, r"FINAL\08_SUIT_TEST")


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


# 1) materials.csv: 材质名 → GUID 列表
mat_guids = collections.defaultdict(list)
with open(os.path.join(IDX, "materials.csv"), newline="", encoding="utf-8", errors="replace") as f:
    for r in csv.DictReader(f):
        name = (r.get("name") or "").strip()
        if not name:
            continue
        gs = [m.group(1) for m in re.finditer(
            r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", r.get("textures") or "")
            if m.group(1) != "00000000-0000-0000-0000-000000000000"]
        if gs:
            mat_guids[name].extend(gs)
print("materials with texture guids:", len(mat_guids))

# 2) texture_pairs.csv: 材质名 → [(texture_path, expected_png, slot)]
mat_pairs = collections.defaultdict(list)
with open(os.path.join(IDX, "texture_pairs.csv"), newline="", encoding="utf-8", errors="replace") as f:
    for r in csv.DictReader(f):
        mat_pairs[(r.get("material") or "").strip()].append(
            (r.get("texture_path", ""), r.get("expected_png", ""), r.get("slot", "")))
print("materials in pairs:", len(mat_pairs))

# 3) mpkdb
con = sqlite3.connect(DB)
cur = con.cursor()
table = {}
for v0, v1, v2, v6 in cur.execute("SELECT v0,v1,v2,v6 FROM info0"):
    try:
        v0 = int(v0)
    except Exception:
        continue
    table.setdefault((v0 >> 32) & M32, (int(v1), int(v2), int(v6)))

# 4) 每个套装目录 -> mtl 里引用的材质名与贴图文件名
report = []
allpacks = collections.Counter()
for suit in sorted(os.listdir(SUITS)):
    d = os.path.join(SUITS, suit, "materials")
    if not os.path.isdir(d):
        continue
    mats = set()
    pngs = set()
    for mtl in glob.glob(os.path.join(d, "*.mtl")):
        txt = open(mtl, encoding="utf-8", errors="replace").read()
        for line in txt.splitlines():
            line = line.strip()
            if line.startswith("newmtl "):
                mats.add(line[7:].strip())
            elif line.startswith("map_"):
                pngs.add(os.path.basename(line.split(None, 1)[1].strip()))
    guids = []
    for m in mats:
        guids.extend(mat_guids.get(m, []))
    guids = list(dict.fromkeys(guids))
    loc = 0
    packs = collections.Counter()
    for g in guids:
        r = table.get(murmur3(f"{g[:2]}/{g}.4".encode()))
        if r:
            loc += 1
            packs[r[1]] += 1
            allpacks[r[1]] += 1
    report.append((suit, len(mats), len(pngs), len(guids), loc, packs.most_common(4)))
    print(f"{suit:22} 材质{len(mats):3} 贴图名{len(pngs):3} GUID{len(guids):4} 可定位{loc:4} 包分布{packs.most_common(4)}")

print("\n全部套装涉及包:", sorted(allpacks.items())[:30])
print("包数量:", len(allpacks))
