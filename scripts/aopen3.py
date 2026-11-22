import struct
from capstone import *

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
sn,va,vs,fo,fs = [s for s in segs if s[0]=="__TEXT_EXEC"][0]

def dis(start_va, end_va):
    o = fo + (start_va - va)
    n = end_va - start_va
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True
    return list(md.disasm(data[o:o+n], start_va))

# 1) 反汇编 resOpen==0 引用点前后
print("=== resOpen==0 附近 (0xa5ba40 - 0xa5bbb0) ===")
for ins in dis(0xfffffff008a5ba40, 0xfffffff008a5bbb0):
    print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}")

# 2) 找函数起点（往前找 pacibsp）
print("\n=== 往前找函数起点 ===")
o = fo + (0xfffffff008a5ba40 - va)
for back in range(0, 0x3000, 4):
    a = 0xfffffff008a5ba40 - back
    oo = fo + (a - va)
    if data[oo:oo+4] == b"\x7f\x23\x03\xd5":
        print(f"  pacibsp @ 0x{a:x}  (距引用点 -0x{back:x})")
        break
