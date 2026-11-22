import struct
from capstone import *
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
START=0xfffffff008df5a74; LEN=0x290
fo=va2fo(START)
md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True
print(f"=== AppleJPEGDriver::newUserClient @0x{START:x} ===")
for ins in md.disasm(data[fo:fo+LEN], START):
    if ins.id==0: continue
    print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}")
