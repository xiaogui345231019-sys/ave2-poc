import struct
from capstone import *
from capstone.arm64 import ARM64_OP_IMM

P = r"E:\IOS18.7.2\work\kext\a14_18.7.2_IOMobileGraphicsFamily"
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
segs_d = {s[0]:s for s in segs}
DC = segs_d["__DATA_CONST"]; EX = segs_d["__TEXT_EXEC"]

# 93 项 selector 表 @0x7dedfb0，stride 0x18
TBL_VA = 0xfffffff007dedfb0
TBL_N  = 93
FIX = 0xfffffff007004000

def read_ptr(va):
    for sn,sva,svs,sfo,sfs in segs:
        if sva <= va < sva+svs and sfs:
            o = sfo + (va-sva)
            q = struct.unpack_from("<Q", data, o)[0]
            if EX[1] <= q < EX[1]+EX[2]: return q
            v = FIX + (q & 0xFFFFFFFF)
            if EX[1] <= v < EX[1]+EX[2]: return v
            return None
    return None

# 找出所有调用 IOSurface 的 handler（在 selector 表里）
ISURF_EXEC = (0xfffffff009e63ac0, 0xfffffff009e63ac0+0x2ddf8)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True

# 先拿到 § 全部 handler 地址
handlers = {}
for i in range(TBL_N):
    h = read_ptr(TBL_VA + i*0x18)
    if h: handlers[i] = h
print(f"=== selector 表解析: {len(handlers)}/{TBL_N} 个非空 handler ===")

# 对每个 handler 反汇编（假设长度 <= 0x600），找 bl->IOSurface
def dis_range(va, ln):
    for sn,sva,svs,sfo,sfs in segs:
        if sva <= va < sva+svs and sfs:
            o = sfo + (va-sva)
            return list(md.disasm(data[o:o+ln], va))
    return []

hits = []
for idx, h in sorted(handlers.items()):
    ins_list = dis_range(h, 0x600)
    targets = []
    for ins in ins_list:
        if ins.id==0: continue
        if ins.mnemonic=="bl" and len(ins.operands)==1 and ins.operands[0].type==ARM64_OP_IMM:
            t = ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
            if ISURF_EXEC[0] <= t < ISURF_EXEC[1]:
                targets.append((ins.address, t))
    if targets:
        hits.append((idx, h, targets))

print(f"\n=== 调 IOSurface 的 selector: {len(hits)} 个 ===")
for idx, h, tg in hits:
    print(f"\n  sel 0x{idx:02x} ({idx:2d})  handler=0x{h:x}")
    for a,t in tg[:8]:
        mark = "  ← *(IOSurface+0x30) 描述符!" if t == 0xfffffff009e72ba4 else ""
        print(f"      0x{a:x} -> 0x{t:x}{mark}")
