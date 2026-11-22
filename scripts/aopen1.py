import struct, re
from capstone import *
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG

KE = r"E:\IOS18.7.2\work\kext\ave2_a14_18.7.2"
data = open(KE,"rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off=32; segs=[]
for _ in range(ncmds):
    cmd,cs = struct.unpack_from("<II", data, off)
    if cmd==0x19:
        sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        v,sz,f,s = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn,v,sz,f,s))
    off+=cs
print("=== AVE2 kext 段 ===")
for s in segs: print(f"  {s[0]:16s} va=0x{s[1]:x} vsize=0x{s[2]:x} fo=0x{s[3]:x} fsize=0x{s[4]:x}")

def fo2va(fo):
    for sn,v,sz,f,s in segs:
        if f <= fo < f+s: return v + (fo-f), sn
    return None, None

# 找 "IOService::open failed" 的 file offset
kw = b"IOService::open failed"
print(f"\n=== 搜 {kw.decode()} ===")
refs = [m.start() for m in re.finditer(re.escape(kw), data)]
print(f"  命中 {len(refs)} 处")
for fo in refs:
    va, sn = fo2va(fo)
    print(f"  fo=0x{fo:x} -> VA 0x{va:x} [{sn}]")

# 也要 "resOpen == 0"
for kw2 in (b"resOpen == 0", b"failed to open one client"):
    r2 = [m.start() for m in re.finditer(re.escape(kw2), data)]
    print(f"\n=== {kw2.decode()}: {len(r2)} 处 ===")
    for fo in r2[:3]:
        va, sn = fo2va(fo)
        print(f"  fo=0x{fo:x} -> VA 0x{va:x} [{sn}]")
