import struct
from capstone import *
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

P = r"E:\IOS18.7.2\work\kext\a12_18.7.2_AppleJPEGDriver"
data = open(P, "rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off=32; segs=[]
for _ in range(ncmds):
    cmd,cmdsize=struct.unpack_from("<II", data, off)
    if cmd==0x19:
        sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va,vs,fo,fs=struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn,va,vs,fo,fs))
    off+=cmdsize
def va2fo(va):
    for sn,sva,svs,sfo,sfs in segs:
        if sva<=va<sva+svs and sfs: return sfo+(va-sva)
    return None

# tsv 给的三个 AppleJPEGDriverUserClient 引用点，往前找构造函数入口
# 先看 0x8dff728 前后
for START in (0xfffffff008dff6f0, 0xfffffff008dff820, 0xfffffff008e00480):
    fo = va2fo(START)
    if fo is None: continue
    print(f"\n=== disasm @0x{START:x} (0x180 bytes) ===")
    md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True
    n=0
    for ins in md.disasm(data[fo:fo+0x180], START):
        if ins.id==0: continue
        print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}")
        n+=1
        if n>60: break
