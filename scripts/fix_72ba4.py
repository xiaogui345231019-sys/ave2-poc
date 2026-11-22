import struct
from capstone import *

P = r"E:\IOS18.7.2\work\kext\a14_18.6.2_com.apple.iokit.IOSurface"
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

# 0x9e72ba4 往前找函数起点
T = 0xfffffff009e72ba4
start = T
for back in range(0, 0x400, 4):
    va = T - back
    f = va2fo(va)
    if f is None: break
    b = data[f:f+4]
    if b == b"\x7f\x23\x03\xd5" or b == b"\x5f\x24\x03\xd5":  # pacibsp / bti c
        start = va; break
print(f"0x9e72ba4 所在函数起点 ≈ 0x{start:x}  (偏移 +0x{T-start:x})")
f = va2fo(start)
print(f"\n=== 函数 0x{start:x} 前 0x60 字节 ===")
for ins in md.disasm(data[f:f+0x60], start):
    if ins.id==0: continue
    print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}")

# 也看看 0x9e72ba4 之后 0x40 字节，判断它是什么性质的调用
print(f"\n=== 0x9e72ba4 附近（判断是否为 import thunk / stub）===")
f2 = va2fo(T)
for ins in md.disasm(data[f2-0x10:f2+0x30], T-0x10):
    if ins.id==0: continue
    print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}")

# 关键：A14 里真正取 +0x30 的三个 getter，看 DCP 是否调用它们
print(f"\n=== DCP 是否调用真正的 +0x30 getter ===")
DCP = r"E:\IOS18.7.2\work\kext\a14_18.7.2_IOMobileGraphicsFamily-DCP"
d2 = open(DCP,"rb").read()
n2 = struct.unpack_from("<I", d2, 16)[0]
off=32; segs2=[]
for _ in range(n2):
    cmd,cs = struct.unpack_from("<II", d2, off)
    if cmd==0x19:
        sn=d2[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va,vs,fo,fs = struct.unpack_from("<QQQQ", d2, off+24)
        segs2.append((sn,va,vs,fo,fs))
    off+=cs
GETTERS = {0xfffffff009e65784,0xfffffff009e667a0,0xfffffff009e6e7ec,0xfffffff009e6e7f8}
for sn,sva,svs,sfo,sfs in segs2:
    if sn!="__TEXT_EXEC": continue
    for ins in md.disasm(d2[sfo:sfo+sfs], sva):
        if ins.id==0: continue
        if ins.mnemonic=="bl" and len(ins.operands)==1:
            try:
                t = ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
                if t in GETTERS:
                    print(f"  0x{ins.address:x} -> 0x{t:x}  (真 +0x30 getter)")
            except: pass
