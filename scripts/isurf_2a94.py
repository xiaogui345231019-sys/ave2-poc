import struct
from capstone import *

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
def va2seg(va):
    for sn,sva,svs,sfo,sfs in segs:
        if sva<=va<sva+svs: return sn

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True

for FN, LABEL in [(0xfffffff009e72a94, "被 +0x150 调用的函数")]:
    f = va2fo(FN)
    print(f"\n=== {LABEL} 0x{FN:x} ===")
    cnt=0
    for ins in md.disasm(data[f:f+0x140], FN):
        if ins.id==0: continue
        mark=""
        if ins.mnemonic=="bl" and ins.operands and ins.operands[0].type==2:
            t=ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
            s=va2seg(t)
            mark = f"   → 0x{t:x}" + (f" [{s}]" if s else " (外部)")
        print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}{mark}")
        cnt+=1
        if cnt>=48: break

# 同时看 +0x170 是什么（找 setter）
print("\n=== [IOSurface+0x170] 的写点 ===")
for sn,sva,svs,sfo,sfs in segs:
    if sn not in ("__TEXT_EXEC","__TEXT"): continue
    for ins in md.disasm(data[sfo:sfo+sfs], sva):
        if ins.id==0: continue
        if ins.mnemonic=="str" and "#0x170" in ins.op_str:
            print(f"  0x{ins.address:x}  {ins.mnemonic} {ins.op_str}")
