# -*- coding: utf-8 -*-
"""把 5 套套装需要的贴图从设备 Patch 包精确拉取并解码回填

链路：mtl 贴图名 → repository GUID → "{g[:2]}/{g}.4" → murmur3(std) →
      Patch.mpkdb (pack, offset, size) → adb dd 拉取 → recipe 解码 → PNG

用法：
  python pull_suit_textures.py --discover        # 找设备上的 Patch 目录
  python pull_suit_textures.py                   # 全量拉取 5 套
  python pull_suit_textures.py --suit 雪狸儿      # 只做一套
"""
import argparse, csv, glob, os, sqlite3, struct, subprocess, sys, collections
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from Crypto.Cipher import AES
import lz4.block as L
import numpy as np
import texture2ddecoder as T
from PIL import Image

M32 = 0xFFFFFFFF
ROOT = r"D:\ReverseKit\projects\apk_yyslscn"
DB = os.path.join(ROOT, r"mpkdb\Patch.new.mpkdb")
REPO = os.path.join(ROOT, r"FINAL\05_INDEX\repository.csv")
SUITS = os.path.join(ROOT, r"FINAL\08_SUIT_TEST")
CACHE = os.path.join(ROOT, "patch_cache")
OUTROOT = os.path.join(ROOT, "suit_textures")

KEY = struct.pack("<4Q", 0x556A586E32723575, 0x38782F913F152867,
                  0x2D3B615062536756, 0x6B59703373367639)
BLOCKS = [4, 5, 6, 8, 10, 12]
DEVICE_DIRS = [
    "/sdcard/Android/data/com.netease.yyslscn/files/Patch",
    "/sdcard/Android/data/com.netease.yyslscn/files",
    "/data/data/com.netease.yyslscn/files/Patch",
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


def aes_head(b):
    n = min((len(b) // 16) * 16, 256)
    return AES.new(KEY, AES.MODE_ECB).decrypt(b[:n]) + b[n:] if n else b


def guess_block(w, h, rs):
    for b in BLOCKS:
        if ((w + b - 1) // b) * ((h + b - 1) // b) * 16 == rs:
            return b
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
    bpp = None
    if blk is None:
        for k in (4, 3):
            if raw_size == w * h * k:
                bpp = k
                break
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
    if bpp:
        a = np.frombuffer(data[:w * h * bpp], dtype=np.uint8)
        if bpp == 4:
            return a.reshape(h, w, 4), w, h, "RGBA"
        return np.dstack([a.reshape(h, w, 3), np.full((h, w, 255), 255, np.uint8)]), w, h, "RGB"
    rgba = T.decode_astc(data, w, h, blk, blk)
    a = np.frombuffer(rgba, dtype=np.uint8)
    if len(a) < w * h * 4:
        return None
    return a[:w * h * 4].reshape(h, w, 4), w, h, "ASTC%dx%d" % (blk, blk)


def adb(args, binary=False, timeout=300):
    cmd = ["adb"] + args
    r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    if binary:
        return r.stdout
    return (r.stdout or b"").decode("utf-8", "replace") + (r.stderr or b"").decode("utf-8", "replace")


def device_path(dev_dir, pack):
    return f"{dev_dir}/Patch{pack}.mpk"


def fetch(dev_dir, pack, off, size, align=4096):
    """按对齐偏移 dd 拉取，再裁掉前缀"""
    os.makedirs(CACHE, exist_ok=True)
    dst = os.path.join(CACHE, f"{pack}_{off}_{size}.bin")
    if os.path.exists(dst) and os.path.getsize(dst) >= size:
        return open(dst, "rb").read()
    start = (off // align) * align
    skip = start // align
    count = ((off - start) + size + align - 1) // align
    src = device_path(dev_dir, pack)
    cmd = f"su -c 'dd if={src} bs={align} skip={skip} count={count} 2>/dev/null'"
    data = adb(["exec-out", cmd], binary=True, timeout=600)
    if len(data) < size:
        return None
    blob = data[off - start: off - start + size]
    with open(dst, "wb") as f:
        f.write(blob)
    return blob


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--suit", default=None)
    ap.add_argument("--discover", action="store_true")
    ap.add_argument("--dev-dir", default=DEVICE_DIRS[0])
    args = ap.parse_args()

    if args.discover:
        print(adb(["devices", "-l"]))
        for d in DEVICE_DIRS:
            print("==", d)
            print(adb(["shell", f"ls {d} 2>/dev/null | head -20"]))
            print(adb(["shell", f"ls {d} 2>/dev/null | wc -l"]))
        return

    # 1) mtl → 贴图名
    suits = [args.suit] if args.suit else sorted(
        d for d in os.listdir(SUITS) if os.path.isdir(os.path.join(SUITS, d, "materials")))
    need = collections.defaultdict(set)
    for suit in suits:
        for mtl in glob.glob(os.path.join(SUITS, suit, "materials", "*.mtl")):
            for line in open(mtl, encoding="utf-8", errors="replace"):
                line = line.strip()
                if line.startswith("map_"):
                    nm = os.path.basename(line.split(None, 1)[1].strip())
                    if nm.lower().endswith(".png"):
                        nm = nm[:-4]
                    need[suit].add(nm)

    # 2) name → guid
    name2guid = {}
    with open(REPO, newline="", encoding="utf-8-sig", errors="replace") as f:
        for r in csv.DictReader(f):
            if (r.get("type") or "") != "Texture2D":
                continue
            nm = (r.get("name") or "").strip()
            if nm and nm not in name2guid:
                name2guid[nm] = r.get("guid")

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

    ok_all = fail_all = miss = 0
    for suit in suits:
        outdir = os.path.join(OUTROOT, suit)
        os.makedirs(outdir, exist_ok=True)
        ok = fail = 0
        for nm in sorted(need[suit]):
            g = name2guid.get(nm)
            if not g:
                miss += 1
                continue
            r = table.get(murmur3(f"{g[:2]}/{g}.4".encode()))
            if not r:
                miss += 1
                continue
            size, pack, off = r
            buf = fetch(args.dev_dir, pack, off, size)
            if not buf:
                fail += 1
                print(f"  [fetch-fail] {suit}/{nm} pack{pack} off{off} size{size}")
                continue
            try:
                d = decode(buf)
            except Exception:
                d = None
            if not d:
                fail += 1
                print(f"  [decode-fail] {suit}/{nm} pack{pack} {size}B")
                continue
            im, w, h, tag = d
            Image.fromarray(im).save(os.path.join(outdir, nm + ".png"))
            ok += 1
        print(f"{suit}: ok={ok} fail={fail}")
        ok_all += ok
        fail_all += fail
    print(f"TOTAL ok={ok_all} fail={fail_all} unmatched={miss}")


if __name__ == "__main__":
    main()
