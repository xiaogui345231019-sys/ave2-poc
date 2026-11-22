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
FIX = 0xfffffff007004000

def in_code(va):
    return (text_lo <= va < text_lo+text_sz) or (exec_lo <= va < exec_lo+exec_sz)

def decode_any(q):
    out = []
    if in_code(q): out.append(q)
    v = FIX + (q & 0xFFFFFFFF)
    if (q >> 32) and in_code(v): out.append(v)
    # PAC-signed pointer: strip top bits, low 32/36 bits may still be offset
    for mask in (0xFFFFFFFF, 0xFFFFFFFFF, 0x7FFFFFFFFF):
        v2 = FIX + (q & mask)
        if in_code(v2) and v2 not in out: out.append(v2)
    return out

for segname in ("__DATA", "__DATA_CONST"):
    lo, sz, fo, fs = segs[segname]
    blob = data[fo:fo+fs]
    print(f"\n=== scanning {segname} (va=0x{lo:x}, {len(blob)} bytes) ===")
    found = []
    for start in range(0, len(blob)-24, 8):
        run = []
        for k in range(80):
            o = start + k*24
            if o+24 > len(blob): break
            q = struct.unpack_from("<Q", blob, o)[0]
            cands = decode_any(q)
            if not cands: break
            ci, si, co, so = struct.unpack_from("<IIII", blob, o+8)
            if ci > 8 or co > 8 or si > 0x200000 or so > 0x200000: break
            run.append((cands[0], ci, si, co, so))
        if len(run) >= 5:
            found.append((start, run))
    # 只保留最长且不重复起点
    best = sorted(found, key=lambda x: -len(x[1]))[:3]
    for start, run in best:
        print(f"  --- candidate @ va 0x{lo+start:x}  entries={len(run)} ---")
        for i, (fn, ci, si, co, so) in enumerate(run[:48]):
            print(f"      idx {i:2d} fn=0x{fn:x} in(s={ci},st=0x{si:x}) out(s={co},st=0x{so:x})")
    if not best:
        print("  (none)")
