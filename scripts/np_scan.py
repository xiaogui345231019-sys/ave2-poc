import struct
from capstone import *
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG

KC = r"E:\IOS18.7.2\work\fw\a14_18.7.2_22H124\kernelcache.release.iphone13.raw"
data = open(KC,"rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off=32; segs=[]
for _ in range(ncmds):
    cmd,cs = struct.unpack_from("<II", data, off)
    if cmd==0x19:
        sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        v,sz,f,s = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn,v,sz,f,s))
    off+=cs

# 字节模式搜 mov w?, #0x2e2 (=0x52805C4? 需按 Rd 变) ；更稳：搜 movk w?, #0xe000, lsl #16 (=0x72A0000?)
# movz wN,#0x2e2 编码: sf=0 opc=10 hw=00 imm16=0x2e2 Rd  => 0x52800000 | (0x2e2<<5) | Rd
# movk wN,#0xe000,lsl16: sf=0 opc=11 hw=01 imm16=0xe000 Rd => 0x72A00000 | (0xe000<<5) | Rd
import re
print("=== 搜 movz wN,#0x2e2 (NotPermitted 低半) ===")
hits = []
for Rd in range(32):
    pat = struct.pack("<I", 0x52800000 | (0x2e2 << 5) | Rd)
    for m in re.finditer(re.escape(pat), data):
        hits.append((m.start(), Rd))
print(f"  共 {len(hits)} 处")
# 对每处，看下一条是不是 movk wN,#0xe000,lsl16
found = []
for fo, Rd in hits:
    if fo+4 > len(data): continue
    nxt = struct.unpack_from("<I", data, fo+4)[0]
    if nxt == (0x72A00000 | (0xe000 << 5) | Rd):
        # 定位 VA
        for sn,v,sz,f,s in segs:
            if f <= fo < f+s:
                found.append((v + (fo-f), sn, fo))
                break
print(f"=== movz #0x2e2 + movk #0xe000 组合: {len(found)} 处 ===")
for va, sn, fo in found[:30]:
    print(f"  0x{va:x}  [{sn}]")
