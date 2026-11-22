import struct
from capstone import *

KC = r"E:\IOS18.7.2\work\fw\a14_18.7.2_22H124\kernelcache.release.iphone13.raw"
data = open(KC,"rb").read()
print(f"KC size = {len(data)}")

# MH_FILESET：找顶层 __TEXT_EXEC
magic = struct.unpack_from("<I", data, 0)[0]
print(f"magic = 0x{magic:x} (0xfeedfacf=MH_MAGIC_64, 0xcffaedfe=MH_FILESET)")
ncmds = struct.unpack_from("<I", data, 16)[0]
off=32; segs=[]
for _ in range(ncmds):
    cmd,cs = struct.unpack_from("<II", data, off)
    if cmd==0x19:
        sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va,vs,fo,fs = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn,va,vs,fo,fs))
    off+=cs
print("=== top-level segments ===")
for s in segs: print(f"  {s[0]:16s} 0x{s[1]:x} +0x{s[2]:x} (file 0x{s[3]:x})")

# 扫 kernel 的 __TEXT_EXEC：找 ldr/ldrsw 从 [x?, #0xdc] 读的地方
EX = [s for s in segs if s[0]=="__TEXT_EXEC"]
if not EX:
    print("no top __TEXT_EXEC"); raise SystemExit
sn,va,vs,fo,fs = EX[0]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True
hits=[]
for ins in md.disasm(data[fo:fo+fs], va):
    if ins.id==0: continue
    if ins.mnemonic in ("ldr","ldrsw","ldur","ldrsw") and "#0xdc" in ins.op_str:
        hits.append((ins.address, ins.mnemonic, ins.op_str))
print(f"\n=== 读 [x?, #0xdc] 的指令: {len(hits)} 处 ===")
for a,m,o in hits[:60]:
    print(f"  0x{a:x}  {m:7s} {o}")
