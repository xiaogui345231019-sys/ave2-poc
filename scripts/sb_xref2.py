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

def fo2va(fo):
    for sn,v,sz,f,s in segs:
        if f <= fo < f + s:
            return v + (fo - f), sn
    return None, None

print("=== 字符串所属段 / VA ===")
for fo_s, name in [(0x9504b4,"iokit-open*"), (0x7afda2,"user-client-class msg"), (0x7b6b1a,"ENTITLEMENT:...")]:
    va, sn = fo2va(fo_s)
    print(f"  0x{fo_s:x} -> VA 0x{va:x} ({sn})  {name}")

targets = {}
for fo_s, name in [(0x9504b4,"iokit-open*"), (0x7afda2,"user-client-class msg"), (0x7b6b1a,"ENTITLEMENT:...")]:
    va, sn = fo2va(fo_s)
    targets[va] = name

sn,va,vs,fo,fs = [s for s in segs if s[0]=="__TEXT_EXEC"][0]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True
prev = {}
hits = {k: [] for k in targets}
cnt = 0
for ins in md.disasm(data[fo:fo+fs], va):
    if ins.id == 0: continue
    cnt += 1
    if ins.mnemonic == "adrp" and len(ins.operands) >= 2:
        r = md.reg_name(ins.operands[0].reg)
        prev[r] = ins.operands[1].imm & 0xFFFFFFFFFFFFFFFF
    elif ins.mnemonic == "add" and len(ins.operands) >= 3:
        if ins.operands[1].type == ARM64_OP_REG and ins.operands[2].type == ARM64_OP_IMM:
            s = md.reg_name(ins.operands[1].reg)
            if s in prev:
                t = (prev[s] + ins.operands[2].imm) & 0xFFFFFFFFFFFFFFFF
                if t in hits:
                    hits[t].append(ins.address)
print(f"\n扫描 {cnt} 条指令")
for k, name in targets.items():
    print(f"\n=== {name} (VA 0x{k:x}) 引用: {len(hits[k])} ===")
    for a in hits[k][:12]:
        print(f"  0x{a:x}")
