# -*- coding: utf-8 -*-
"""GUID → mpkdb → (pack, offset, size)；对 pack 在本地有副本的直接解码"""
import csv, os, sqlite3, struct, sys, collections, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from Crypto.Cipher import AES
import lz4.block as L
import numpy as np
import texture2ddecoder as T
from PIL import Image

M32 = 0xFFFFFFFF
ROOT = r"D:\ReverseKit\projects\apk_yyslscn"
MC = os.path.join(ROOT, r"FINAL\05_INDEX\materials.csv")
DB = os.path.join(ROOT, r"mpkdb\Patch.new.mpkdb")
LOCAL_PACKS = {2: os.path.join(ROOT, r"pack_probe\Patch2.mpk")}
OUT = os.path.join(ROOT, "real_tex")
KEY = struct.pack("<4Q", 0x556A586E32723575, 0x38782F913F152867,
                  0x2D3B615062536756, 0x6B59703373367639)
BLOCKS = [4, 5, 6, 8, 10, 12]


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


def aes_head(b):
    n = min((len(b) // 16) * 16, 256)
    return AES.new(KEY, AES.MODE_ECB).decrypt(b[:n]) + b[n:] if n else b


def guess_block(w, h, rs):
    for b in BLOCKS:
        if ((w + b - 1) // b) * ((h + b - 1) // b) * 16 == rs:
            return b
    return None


def guess_raw(w, h, rs):
    for k in (4, 3, 2, 1):
        if rs == w * h * k:
            return k
    return None


def decode(buf):
    if len(buf) < 0x40 or buf[0x38:0x3c] != b"ZZZX":
        return None
    blob_size, w, h, depth, pitch, raw_size = struct.unpack_from("<IHHHHI", buf, 0x28)
    if not (0 < w <= 8192 and 0 < h <= 8192 and 0 < raw_size <= 64 << 20):
        return None
    if blob_size < 0x18 or blob_size > len(buf):
        return None
    blk = guess_block(w, h, raw_size)
    bpp = None if blk is not None else guess_raw(w, h, raw_size)
    if blk is None and bpp is None:
        return None
    end = min(0x38 + blob_size - 16, len(buf))
    payload = buf[0x40:end]
    data = None
    for cand in (aes_head(payload), payload):
        try:
            o = L.decompress(cand, uncompressed_size=raw_size)
            if len(o) == raw_size:
                data = o
                break
        except Exception:
            pass
    if data is None and len(payload) >= raw_size:
        data = payload[:raw_size]
    if data is None:
        return None
    if bpp is not None:
        a = np.frombuffer(data[:w * h * bpp], dtype=np.uint8)
        if bpp == 4:
            return a.reshape(h, w, 4), w, h, bpp
        if bpp == 3:
            return np.dstack([a.reshape(h, w, 3), np.full((h, w, 255), 255, np.uint8)]), w, h, bpp
        return None
    rgba = T.decode_astc(data, w, h, blk, blk)
    a = np.frombuffer(rgba, dtype=np.uint8)
    if len(a) < w * h * 4:
        return None
    return a[:w * h * 4].reshape(h, w, 4), w, h, blk


def main():
    guids = []
    with open(MC, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            for m in re.finditer(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", r.get("textures") or ""):
                g = m.group(1)
                if g != "00000000-0000-0000-0000-000000000000":
                    guids.append((g, r.get("row"), r.get("name")))
    print("material texture refs:", len(guids))

    con = sqlite3.connect(DB)
    cur = con.cursor()
    table = {}
    for v0, v1, v2, v6 in cur.execute("SELECT v0,v1,v2,v6 FROM info0"):
        try:
            v0 = int(v0)
        except Exception:
            continue
        table.setdefault((v0 >> 32) & M32, (int(v1), int(v2), int(v6)))

    hits = []
    packs = collections.Counter()
    for g, row, name in guids:
        h = murmur3(f"{g[:2]}/{g}.4".encode())
        r = table.get(h)
        if r:
            hits.append((g, row, name, r[1], r[2], r[0]))
            packs[r[1]] += 1
    print(f"hit {len(hits)}/{len(guids)}")
    print("pack distribution:", packs.most_common(20))

    os.makedirs(OUT, exist_ok=True)
    by_pack = collections.defaultdict(list)
    for t in hits:
        by_pack[t[3]].append(t)
    print("packs with local copy:", [p for p in by_pack if p in LOCAL_PACKS])

    for pack, items in sorted(by_pack.items()):
        if pack not in LOCAL_PACKS:
            continue
        mpk = open(LOCAL_PACKS[pack], "rb").read()
        ok = fail = 0
        for g, row, name, _, off, size in items:
            buf = mpk[off:off + size]
            try:
                r = decode(buf)
            except Exception:
                r = None
            if r is None:
                fail += 1
                continue
            im, w, h, tag = r
            Image.fromarray(im).save(os.path.join(OUT, f"pack{pack}_{row}_{g[:8]}_{w}x{h}.png"))
            ok += 1
        print(f"pack {pack}: items {len(items)} ok {ok} fail {fail}")


if __name__ == "__main__":
    main()
