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
EX = [s for s in segs if s[0]=="__TEXT_EXEC"][0]

def va2fo(va):
    for sn,sva,svs,sfo,sfs in segs:
        if sva<=va<sva+svs and sfs: return sfo+(va-sva)
    return None

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True

# 目标：0x9cec608 附近的函数；以及 0x9cee384
for CAND in (0xfffffff009cec608, 0xfffffff009cee384, 0xfffffff009cf1060):
    fo = va2fo(CAND)
    if fo is None: continue
    # 往前找 pacibsp 起点（最多 0x600）
    start = CAND
    for back in range(0, 0x600, 4):
        va = CAND - back
        f = va2fo(va)
        if f is None: break
        if data[f:f+4] == b"\x7f\x23\x03\xd5":  # pacibsp
            start = va; break
    print(f"\n=== 调用点 0x{CAND:x} 所在函数起点 ≈ 0x{start:x} (偏移 -0x{CAND-start:x}) ===")
    f = va2fo(start)
    # 反汇编 0x120 字节，看参数用法与调用的 IOSurface 函数
    for ins in md.disasm(data[f:f+0x120], start):
        if ins.id==0: continue
        mark=""
        if ins.mnemonic=="bl" and len(ins.operands)==1 and ins.operands[0].type==ARM64_OP_IMM:
            t=ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
            if 0xfffffff009e63ac0 <= t < 0xfffffff009e918b8:
                mark = "   ← IOSurface"
                if t==0xfffffff009e72ba4: mark = "   ← *(IOSurface+0x30) BACKING"
        print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}{mark}")
