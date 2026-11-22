import struct
from capstone import *
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM

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
BASE = 0xfffffff007004000
def f2v(fo): return BASE + fo

# 目标字符串的 VA
targets = {0x9504b4: "iokit-open*", 0x7afda2: "iokit-user-client-class msg",
           0x7b6b1a: "ENTITLEMENT:...exception.iokit-user-client-class"}

# 扫 __TEXT_EXEC 找 adrp+add 指向这些串
sn,va,vs,fo,fs = [s for s in segs if s[0]=="__TEXT_EXEC"][0]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True

want = {}
for fo_s, name in targets.items():
    want[fo_s] = name

hits = {k: [] for k in targets}
prev_adrp = {}   # reg -> (addr, target)
code = data[fo:fo+fs]
cnt = 0
for ins in md.disasm(code, va):
    if ins.id == 0: continue
    cnt += 1
    if ins.mnemonic == "adrp" and len(ins.operands) >= 2:
        r = md.reg_name(ins.operands[0].reg)
        imm = ins.operands[1].imm & 0xFFFFFFFFFFFFFFFF
        prev_adrp[r] = (ins.address, imm)
    elif ins.mnemonic == "add" and len(ins.operands) >= 3:
        d = md.reg_name(ins.operands[0].reg)
        s = md.reg_name(ins.operands[1].reg)
        if s in prev_adrp and ins.operands[2].type == ARM64_OP_IMM:
            tgt = (prev_adrp[s][1] + ins.operands[2].imm) & 0xFFFFFFFFFFFFFFFF
            for fo_s, name in want.items():
                v = f2v(fo_s)
                if tgt == v:
                    hits[fo_s].append((ins.address, d))
print(f"扫描指令数: {cnt}")
for fo_s, name in want.items():
    print(f"\n=== {name} (VA 0x{f2v(fo_s):x}) 引用点: {len(hits[fo_s])} ===")
    for a, r in hits[fo_s][:10]:
        print(f"  0x{a:x}  -> {r}")
