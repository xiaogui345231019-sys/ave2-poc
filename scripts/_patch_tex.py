# -*- coding: utf-8 -*-
"""用修正后的 recipe（LZ4 + 前256B AES + raw_size 反推块尺寸）解 Patch*.mpk 内联容器"""
import os, struct, sys, collections
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from Crypto.Cipher import AES
import lz4.block as L
import numpy as np
import texture2ddecoder as T
from PIL import Image, ImageDraw

PACK = sys.argv[1] if len(sys.argv) > 1 else r"D:\ReverseKit\projects\apk_yyslscn\pack_probe\Patch2.mpk"
OUT = sys.argv[2] if len(sys.argv) > 2 else r"D:\ReverseKit\projects\apk_yyslscn\patch_tex"
LIMIT = int(sys.argv[3]) if len(sys.argv) > 3 else 999999

KEY = struct.pack("<4Q", 0x556A586E32723575, 0x38782F913F152867,
                  0x2D3B615062536756, 0x6B59703373367639)
MAGIC = b"\x02\x02\x02\x01"
BLOCKS = [4, 5, 6, 8, 10, 12]


def aes_head(b):
    n = min((len(b) // 16) * 16, 256)
    return AES.new(KEY, AES.MODE_ECB).decrypt(b[:n]) + b[n:] if n else b


def guess_block(w, h, rs):
    for b in BLOCKS:
        if ((w + b - 1) // b) * ((h + b - 1) // b) * 16 == rs:
            return b
    return None


def guess_raw(w, h, rs):
    n = w * h
    for k in (4, 3, 2, 1):
        if rs == n * k:
            return k
    return None


def to_rgba(data, w, h, bpp):
    a = np.frombuffer(data[:w * h * bpp], dtype=np.uint8)
    if bpp == 4:
        return a.reshape(h, w, 4)
    if bpp == 3:
        return np.dstack([a.reshape(h, w, 3), np.full((h, w, 1), 255, np.uint8)])
    if bpp == 2:
        v = np.frombuffer(data[:w * h * 2], dtype=np.uint16)[:w * h]
        if len(v) < w * h:
            return None
        r = (((v >> 11) & 0x1F) * 255 // 31).astype(np.uint8)
        g = (((v >> 5) & 0x3F) * 255 // 63).astype(np.uint8)
        b = ((v & 0x1F) * 255 // 31).astype(np.uint8)
        return np.dstack([r.reshape(h, w), g.reshape(h, w), b.reshape(h, w),
                          np.full((h, w), 255, np.uint8)])
    if bpp == 1:
        g = a.reshape(h, w)
        return np.dstack([g, g, g, np.full((h, w), 255, np.uint8)])
    return None


def decode(buf):
    if len(buf) < 0x40 or buf[0x38:0x3c] != b"ZZZX":
        return None
    fmt = buf[5]
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
    if len(payload) <= 0:
        return None
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
        im = to_rgba(data, w, h, bpp)
        return None if im is None else (im, w, h, fmt, bpp, len(payload), len(data))
    rgba = T.decode_astc(data, w, h, blk, blk)
    a = np.frombuffer(rgba, dtype=np.uint8)
    if len(a) < w * h * 4:
        return None
    return a[:w * h * 4].reshape(h, w, 4), w, h, fmt, blk, len(payload), len(data)


def main():
    os.makedirs(OUT, exist_ok=True)
    mpk = open(PACK, "rb").read()
    print("pack size MB", round(len(mpk) / 1048576, 1))
    pos = 0
    n_container = 0
    ok = 0
    fail = 0
    dims = collections.Counter()
    while True:
        i = mpk.find(MAGIC, pos)
        if i < 0:
            break
        pos = i + 4
        if i + 0x40 > len(mpk):
            break
        n_container += 1
        if n_container > LIMIT:
            break
        try:
            r = decode(mpk[i:i + (64 << 20)])
        except Exception:
            fail += 1
            continue
        if r is None:
            fail += 1
            continue
        im, w, h, fmt, tag, plen, dlen = r
        Image.fromarray(im).save(os.path.join(OUT, "p%05d_%dx%d.png" % (i, w, h)))
        ok += 1
        dims[(w, h)] += 1
    print(f"containers={n_container} ok={ok} fail={fail}")
    for (w, h), c in dims.most_common(20):
        print(f"  {w}x{h}\t{c}")


if __name__ == "__main__":
    main()
