import struct
P = r"E:\IOS18.7.2\work\kext\a14_18.6.2_AppleJPEGDriver"
data = open(P, "rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off = 32; segs = {}
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        sn = data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va, vs, fo, fs = struct.unpack_from("<QQQQ", data, off+24)
        segs[sn] = (va, vs, fo, fs)
    off += cmdsize

text_lo, text_sz, text_fo, text_fs = segs["__TEXT"]
exec_lo, exec_sz, exec_fo, exec_fs = segs["__TEXT_EXEC"]
dc_lo, dc_sz, dc_fo, dc_fs = segs["__DATA_CONST"]

def in_code(va):
    return (text_lo <= va < text_lo+text_sz) or (exec_lo <= va < exec_lo+exec_sz)

const = data[dc_fo:dc_fo+dc_fs]
FIXUP_BASE = 0xfffffff007004000

def decode(q):
    cands = set()
    if in_code(q):
        cands.add(("raw", q))
    v = FIXUP_BASE + (q & 0xFFFFFFFF)
    if (q >> 32) and in_code(v):
        cands.add(("fixup", v))
    return cands

# 扫 24 字节 stride 的连续项
candidates = []
for start in range(0, len(const)-24, 8):
    run = []
    for k in range(64):
        o = start + k*24
        if o+24 > len(const): break
        q = struct.unpack_from("<Q", const, o)[0]
        d = decode(q)
        if not d: break
        kind, va = list(d)[0]
        ci, si, co, so = struct.unpack_from("<IIII", const, o+8)
        # 合理性：input/output 计数与尺寸不应过大
        if ci > 8 or co > 8 or si > 0x100000 or so > 0x100000: break
        run.append((va, ci, si, co, so))
    if len(run) >= 6:
        candidates.append((start, run))

# 去重（取最长的几条）
seen = set()
print(f"=== candidate dispatch tables: {len(candidates)} ===")
for start, run in candidates:
    key = (start, len(run))
    if key in seen: continue
    seen.add(key)
    if len(run) < 6: continue
    va = dc_lo + start
    print(f"\n--- table @ file 0x{dc_fo+start:x}  VA 0x{va:x}  entries={len(run)} ---")
    for i, (fn, ci, si, co, so) in enumerate(run[:40]):
        print(f"    idx {i:2d}  fn=0x{fn:x}  in(s={ci}, st=0x{si:x})  out(s={co}, st=0x{so:x})")
