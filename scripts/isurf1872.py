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

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True

print("=== 18.7.2 里 0x9e72ba4 是什么 ===")
f = va2fo(0xfffffff009e72ba4)
if f is None:
    print("  不在任何段内")
else:
    for ins in md.disasm(data[f-8:f+0x10], 0xfffffff009e72b9c):
        if ins.id==0: continue
        print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}")

# 用 18.7.2 重新扫 DCP 调用的那几个 IOSurface 函数
print("\n=== DCP 调用的 IOSurface 函数（用 18.7.2 解析）===")
CALLS = [0xfffffff009e72ba4, 0xfffffff009e72cec, 0xfffffff009e792b4,
         0xfffffff009e72ed0, 0xfffffff009e72c80, 0xfffffff009e72cf8,
         0xfffffff009e7423c]
for a in CALLS:
    f = va2fo(a)
    if f is None:
        print(f"  0x{a:x}  不在段内")
        continue
    print(f"  --- 0x{a:x} ---")
    cnt=0
    for ins in md.disasm(data[f:f+0x28], a):
        if ins.id==0: continue
        print(f"      0x{ins.address:x}  {ins.mnemonic:8s} {ins.op_str}")
        cnt+=1
        if ins.mnemonic in ("ret","retab") or cnt>=6: break
