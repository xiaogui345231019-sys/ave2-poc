import struct
from capstone import *

P = r"E:\IOS18.7.2\work\kext\a12_18.7.2_AppleJPEGDriver"
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
def va2seg(va):
    for sn,sva,svs,sfo,sfs in segs:
        if sva<=va<sva+svs: return sn

FIX = 0xfffffff007004000
VT = 0xfffffff007b93bd8   # AppleJPEGDriverUserClient 实例 vtable

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True

print("=== vtable 0x7b93bd8 关键槽 ===")
for soff in (0x2b0, 0x360, 0x2c0):
    va = VT + soff
    f = va2fo(va)
    if f is None: 
        print(f"  +0x{soff:x} 无"); continue
    q = struct.unpack_from("<Q", data, f)[0]
    v = FIX + (q & 0xFFFFFFFF)
    print(f"  +0x{soff:03x} -> 0x{v:x}  (seg {va2seg(v)})")

# 反汇编 +0x360 与 +0x2b0 目标
for soff, label in ((0x360,"初始化#1 (+0x360)"), (0x2b0,"初始化#2 (+0x2b0)")):
    va = VT + soff
    f = va2fo(va)
    q = struct.unpack_from("<Q", data, f)[0]
    tgt = FIX + (q & 0xFFFFFFFF)
    ft = va2fo(tgt)
    if ft is None:
        print(f"\n=== {label} 0x{tgt:x} 不在本 kext ===")
        continue
    print(f"\n=== {label} 0x{tgt:x} ===")
    cnt=0
    for ins in md.disasm(data[ft:ft+0x160], tgt):
        if ins.id==0: continue
        mark=""
        if ins.mnemonic=="bl" and ins.operands and ins.operands[0].type==2:
            t=ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
            s=va2seg(t)
            mark = f"   → 0x{t:x}" + (f" [{s}]" if s else " (外部)")
        print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}{mark}")
        cnt+=1
        if cnt>=30: break
