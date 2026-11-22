import struct
from capstone import *

# tsv 的地址属于 A12/18.7.2 的 kext
P = r"E:\IOS18.7.2\work\kext\a12_18.7.2_AppleJPEGDriver"
data = open(P, "rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off=32; segs=[]
for _ in range(ncmds):
    cmd,cmdsize = struct.unpack_from("<II", data, off)
    if cmd==0x19:
        sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va,vs,fo,fs = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn,va,vs,fo,fs))
    off+=cmdsize
print("=== A12/18.7.2 AppleJPEGDriver segments ===")
for s in segs: print(f"  {s[0]:14s} va=0x{s[1]:x} size=0x{s[2]:x} foff=0x{s[3]:x}")

def va2fo(va):
    for sn,sva,svs,sfo,sfs in segs:
        if sva<=va<sva+svs and sfs: return sfo+(va-sva)
    return None

START = 0xfffffff008dff9e4
LEN   = 0x174
fo = va2fo(START)
print(f"\n=== IOUserClientDefaultLocking @0x{START:x} (fo=0x{fo:x}) ===")
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True
code = data[fo:fo+LEN]
for ins in md.disasm(code, START):
    if ins.id==0: continue
    print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}")
