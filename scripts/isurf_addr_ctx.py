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

for SITE in (0xfffffff009e6f190, 0xfffffff009e89b1c, 0xfffffff009e89f7c):
    f = va2fo(SITE)
    if f is None: continue
    # 往前找函数起点
    start = SITE
    for back in range(0,0x800,4):
        va = SITE-back
        ff = va2fo(va)
        if ff is None: break
        if data[ff:ff+4]==b"\x7f\x23\x03\xd5":
            start=va; break
    print(f"\n=== 引用点 0x{SITE:x}  函数起点 0x{start:x} (偏移 +0x{SITE-start:x}) ===")
    # 从函数起点反向找到引用点前后 0x60 字节
    a = max(start, SITE-0x40)
    f2 = va2fo(a)
    for ins in md.disasm(data[f2:f2+0xa0], a):
        if ins.id==0: continue
        mark = "  <<< 引用 IOSurfaceAddress" if ins.address==SITE else ""
        print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}{mark}")
