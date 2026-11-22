import struct
from capstone import *
from capstone.arm64 import ARM64_OP_IMM

# IOSurface kext 的代码段范围（用于判断 bl 目标是否落在其中）
ISURF_RANGES = [
    (0xfffffff0076fd580, 0xfffffff0076fd580+0x6196),   # __TEXT
    (0xfffffff009e63ac0, 0xfffffff009e63ac0+0x2ddf8),  # __TEXT_EXEC
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

def in_isurf(v):
    return any(lo <= v < lo+sz for lo,sz in ISURF_RANGES)

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
        print(f"\n=== {label}: load failed {e}"); continue
    print(f"\n=== {label} ===")
    for sn,va,vs,fo,fs in segs:
        if sn != "__TEXT_EXEC": continue
        hits = []
        for ins in md.disasm(data[fo:fo+fs], va):
            if ins.id==0: continue
            if ins.mnemonic in ("bl","b") and len(ins.operands)==1 and ins.operands[0].type==ARM64_OP_IMM:
                tgt = ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
                if ins.mnemonic=="bl" and in_isurf(tgt):
                    hits.append((ins.address, tgt))
        print(f"  __TEXT_EXEC bl->IOSurface: {len(hits)} 处")
        for a,t in hits:
            print(f"    0x{a:x} -> 0x{t:x}")
