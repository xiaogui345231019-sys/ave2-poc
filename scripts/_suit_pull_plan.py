# -*- coding: utf-8 -*-
"""闆嫺鍎跨瓑濂楄璐村浘锛氬悕绉扳啋GUID(repository)鈫抦urmur鈫抦pkdb鈫?pack,offset,size)"""
import csv, os, sqlite3, struct, sys, collections, glob
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
M32 = 0xFFFFFFFF
ROOT = r"D:\ReverseKit\projects\apk_yyslscn"
DB = os.path.join(ROOT, r"mpkdb\Patch.new.mpkdb")
REPO = os.path.join(ROOT, r"FINAL\05_INDEX\repository.csv")
SUITS = os.path.join(ROOT, r"FINAL\08_SUIT_TEST")

TARGETS = [
    "lyxk_W_tops4_d", "lyxk_W_tops4_n", "lyxk_W_tops4_m", "lyxk_W_tops4_t",
    "lyxk_W_tops4_detail", "mesh_lyxk_w_body", "Mesh_lyxk_W_body",
]


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


# 1) 鏀堕泦濂楄 mtl 寮曠敤鐨勮创鍥惧悕
need = set()
for suit in sorted(os.listdir(SUITS)):
    d = os.path.join(SUITS, suit, "materials")
    if not os.path.isdir(d):
        continue
    for mtl in glob.glob(os.path.join(d, "*.mtl")):
        for line in open(mtl, encoding="utf-8", errors="replace"):
            line = line.strip()
            if line.startswith("map_"):
                nm = os.path.basename(line.split(None, 1)[1].strip())
                if nm.lower().endswith(".png"):
                    nm = nm[:-4]
                need.add(nm)
print("suit texture names:", len(need))

# 2) repository: name -> guid (Texture2D 浼樺厛)
name2guid = {}
with open(REPO, newline="", encoding="utf-8-sig", errors="replace") as f:
    for r in csv.DictReader(f):
        if (r.get("type") or "") != "Texture2D":
            continue
        nm = (r.get("name") or "").strip()
        if nm and nm not in name2guid:
            name2guid[nm] = (r.get("guid"), r.get("folder"))
print("Texture2D entries:", len(name2guid))

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

hit_name = 0
hit_loc = 0
packs = collections.Counter()
missing_name = []
missing_loc = []
rows = []
for nm in sorted(need):
    e = name2guid.get(nm)
    if not e:
        missing_name.append(nm)
        continue
    hit_name += 1
    g = e[0]
    if not g:
        missing_loc.append((nm, g, e[1]))
        continue
    r = table.get(murmur3(f"{g[:2]}/{g}.4".encode()))
    if r:
        hit_loc += 1
        packs[r[1]] += 1
        rows.append((nm, g, e[1], r[1], r[2], r[0]))
    else:
        missing_loc.append((nm, g, e[1]))

print(f"鍚嶅瓧鎵惧埌 {hit_name}/{len(need)}锛沵pkdb 瀹氫綅 {hit_loc}/{hit_name}")
print("鍖呭垎甯?", packs.most_common(12))
print("\n鑳藉畾浣嶆牱渚?")
for t in rows[:12]:
    print("  ", t)
print("\n鍚嶅瓧缂哄け鏍蜂緥:", missing_name[:8])
print("瀹氫綅澶辫触鏍蜂緥:", missing_loc[:6])

