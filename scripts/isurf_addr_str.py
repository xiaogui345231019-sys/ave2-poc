import struct
from capstone import *
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG

P = r"E:\IOS18.7.2\work\kext\a14_18.7.2_com.apple.iokit.IOSurface"
data = open(P,"rb").read()
n = struct.unpack_from("<I", data, 16)[0]
off=32; segs=[]
for _ in range(n):
    cmd,cs = struct.unpack_from("<II", data, off)
    if cmd==0x19:
        sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va,vs,fo,fs = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn,va,vs,fo,fs))
    off+=cs

def va2fo(va):
    for sn,sva,svs,sfo,sfs in segs:
        if sva<=va<sva+svs and sfs: return sfo+(va-sva)
    return None

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True

# 1) 找 "IOSurfaceAddress" 字符串
idx = data.find(b"IOSurfaceAddress\x00")
print(f"strings 'IOSurfaceAddress' at file 0x{idx:x}")
# 多个可能
import re
for m in re.finditer(rb"IOSurfaceAddress[A-Za-z]*\x00", data):
    print(f"  file 0x{m.start():x}: {m.group()[:-1].decode()}")

# 2) 找引用该字符串的 adrp+add
STRVAS = set()
for m in re.finditer(rb"IOSurfaceAddress\x00", data):
    for sn,sva,svs,sfo,sfs in segs:
        if sfo <= m.start() < sfo+sfs:
            STRVAS.add(sva + (m.start()-sfo))
print(f"\n字符串 VA: {[hex(x) for x in STRVAS]}")

if STRVAS:
    print("\n=== 引用该字符串的 adrp+add ===")
    for sn,sva,svs,sfo,sfs in segs:
        if sn not in ("__TEXT_EXEC","__TEXT"): continue
        regs={}
        for ins in md.disasm(data[sfo:sfo+sfs], sva):
            if ins.id==0: continue
            try:
                if ins.mnemonic=="adrp" and len(ins.operands)==2 and ins.operands[0].type==ARM64_OP_REG:
                    regs[md.reg_name(ins.operands[0].reg)] = (ins.operands[1].imm & 0xFFFFFFFFFFFFFFFF)
                elif ins.mnemonic=="add" and len(ins.operands)==3 and ins.operands[0].type==ARM64_OP_REG and ins.operands[1].type==ARM64_OP_REG and ins.operands[2].type==ARM64_OP_IMM:
                    b = md.reg_name(ins.operands[1].reg)
                    if b in regs:
                        t=(regs[b]+ins.operands[2].imm)&0xFFFFFFFFFFFFFFFF
                        if t in STRVAS:
                            print(f"  0x{ins.address:x}  ({sn})")
                        regs.pop(b,None)
            except Exception: pass
