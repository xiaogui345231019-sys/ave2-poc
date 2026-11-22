import struct
from capstone import *
from capstone.arm64 import ARM64_OP_IMM

FIX = 0xfffffff007004000
TARGETS_VA = {0xfffffff009cec5e0: "backing+memset 主函数", 0xfffffff009cecf90: "尾调点"}

KEYS = [
    ("IOMobileGraphicsFamily-DCP", r"E:\IOS18.7.2\work\kext\a14_18.7.2_IOMobileGraphicsFamily-DCP"),
    ("AppleMobileDispH13P-DCP",    r"E:\IOS18.7.2\work\kext\a14_18.7.2_AppleMobileDispH13P-DCP"),
    ("IOMobileGraphicsFamily",     r"E:\IOS18.7.2\work\kext\a14_18.7.2_IOMobileGraphicsFamily"),
]

def load(P):
    data = open(P,"rb").read()
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off=32; segs=[]
    for _ in range(ncmds):
        cmd,cmdsize = struct.unpack_from("<II", data, off)
        if cmd==0x19:
            sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
            va,vs,fo,fs = struct.unpack_from("<QQQQ", data, off+24)
            segs.append((sn,va,vs,fo,fs))
        off+=cmdsize
    return data, segs

# 1) 找 0x9cecf90 所在函数起点
data, segs = load(KEYS[0][1])
def va2fo(segs, data, va):
    for sn,sva,svs,sfo,sfs in segs:
        if sva<=va<sva+svs and sfs: return sfo+(va-sva)
    return None
fn_start = 0xfffffff009cecf90
for back in range(0, 0x800, 4):
    va = 0xfffffff009cecf90 - back
    f = va2fo(segs, data, va)
    if f is None: break
    if data[f:f+4] == b"\x7f\x23\x03\xd5":
        fn_start = va; break
print(f"0x9cecf90 所在函数起点 ≈ 0x{fn_start:x}")
TARGETS_VA[fn_start] = "外层函数"

# 2) 扫所有 kext 的 __DATA_CONST 找指向这些 VA 的指针（vtable 槽）
print("\n=== vtable 槽引用（chained-fixup 解码）===")
for label, P in KEYS:
    d2, s2 = load(P)
    for sn,sva,svs,sfo,sfs in s2:
        if sn != "__DATA_CONST": continue
        blob = d2[sfo:sfo+sfs]
        for o in range(0, len(blob)-8, 8):
            q = struct.unpack_from("<Q", blob, o)[0]
            if q == 0: continue
            v = FIX + (q & 0xFFFFFFFF)
            if v in TARGETS_VA:
                slot = sva + o
                print(f"  [{label}] slot 0x{slot:x}  -> 0x{v:x}  ({TARGETS_VA[v]})")

# 3) 查 peer vtable 0x7c69380 的几个槽，看是否命中
print("\n=== peer vtable 0x7c69380 关键槽 ===")
d3, s3 = load(KEYS[1][1])
for soff in (0x710, 0x718, 0x720, 0x738, 0x938, 0x848):
    va = 0xfffffff007c69380 + soff
    f = va2fo(s3, d3, va)
    if f is None: continue
    q = struct.unpack_from("<Q", d3, f)[0]
    v = FIX + (q & 0xFFFFFFFF)
    print(f"  +0x{soff:03x} -> 0x{v:x}")
