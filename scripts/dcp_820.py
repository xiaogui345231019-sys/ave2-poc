import struct
from capstone import *
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG

P = r"E:\IOS18.7.2\work\kext\a14_18.7.2_IOMobileGraphicsFamily-DCP"
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

def va2fo(va):
    for sn,sva,svs,sfo,sfs in segs:
        if sva<=va<sva+svs and sfs: return sfo+(va-sva)
    return None

EX = [s for s in segs if s[0]=="__TEXT_EXEC"][0]
print(f"__TEXT_EXEC 0x{EX[1]:x} +0x{EX[2]:x}")

# 反汇编 0x9cecf4c 外层函数
START = 0xfffffff009cecf4c
fo = va2fo(START)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True
print(f"\n=== 外层函数 0x9cecf4c ===")
for ins in md.disasm(data[fo:fo+0x80], START):
    if ins.id==0: continue
    mark=""
    if ins.mnemonic=="bl" and len(ins.operands)==1 and ins.operands[0].type==ARM64_OP_IMM:
        t=ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
        if 0xfffffff009e63ac0 <= t < 0xfffffff009e918b8: mark="  ← IOSurface"
        if t == 0xfffffff009cec5e0: mark="  ← backing+memset 主函数"
    print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}{mark}")

# 找 blraa [xN, #0x820] 的调用点（即调用 vtable+0x820）
print(f"\n=== 扫 blraa/braa 到 +0x820 槽的调用点 ===")
hits=[]
for sn,sva,svs,sfo,sfs in segs:
    if sn != "__TEXT_EXEC": continue
    for ins in md.disasm(data[sfo:sfo+sfs], sva):
        if ins.id==0: continue
        if ins.mnemonic in ("blraa","braa","blr","blr") and ins.op_str:
            if "#0x820" in ins.op_str or ", #0x820" in ins.op_str:
                hits.append((ins.address, ins.mnemonic, ins.op_str))
print(f"  命中 {len(hits)} 处")
for a,m,o in hits[:20]:
    print(f"    0x{a:x}  {m} {o}")
