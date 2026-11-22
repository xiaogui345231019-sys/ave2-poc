import struct
from capstone import *
from capstone.arm64 import ARM64_OP_IMM

# 只用 IOSurface 独有的 __TEXT_EXEC（0x76xxxxx 是所有 kext 共享的 __TEXT 区，会误命中）
ISURF_EXEC = (0xfffffff009e63ac0, 0xfffffff009e63ac0+0x2ddf8)

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

def in_isurf(v):
    return ISURF_EXEC[0] <= v < ISURF_EXEC[1]

TARGETS = [
    ("IOMobileGraphicsFamily", r"E:\IOS18.7.2\work\kext\a14_18.7.2_IOMobileGraphicsFamily"),
    ("IOMobileGraphicsFamily-DCP", r"E:\IOS18.7.2\work\kext\a14_18.7.2_IOMobileGraphicsFamily-DCP"),
    ("AppleMobileDispH13P-DCP", r"E:\IOS18.7.2\work\kext\a14_18.7.2_AppleMobileDispH13P-DCP"),
]

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True
for label, P in TARGETS:
    try:
        data, segs = load(P)
    except Exception as e:
        print(f"\n=== {label}: load failed: {e}"); continue
    print(f"\n=== {label} ===")
    for sn,va,vs,fo,fs in segs:
        print(f"  {sn:14s} 0x{va:x} +0x{vs:x}")
    for sn,va,vs,fo,fs in segs:
        if sn != "__TEXT_EXEC": continue
        hits = []
        for ins in md.disasm(data[fo:fo+fs], va):
            if ins.id==0: continue
            if ins.mnemonic=="bl" and len(ins.operands)==1 and ins.operands[0].type==ARM64_OP_IMM:
                tgt = ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
                if in_isurf(tgt):
                    hits.append((ins.address, tgt))
        print(f"  >>> bl->IOSurface(__TEXT_EXEC): {len(hits)} 处")
        for a,t in hits:
            print(f"      0x{a:x}  -> 0x{t:x}")
