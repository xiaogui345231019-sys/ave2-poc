import struct
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

targets = {
    0xfffffff0072933d9: "IOService::open failed (A)",
    0xfffffff0072d3835: "IOService::open failed (B)",
    0xfffffff0072933ad: "resOpen == 0",
    0xfffffff007293386: "failed to open one client (A)",
    0xfffffff0072d37f0: "failed to open one client (B)",
}

sn,va,vs,fo,fs = [s for s in segs if s[0]=="__TEXT_EXEC"][0]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True
prev = {}
hits = {k: [] for k in targets}
n = 0
for ins in md.disasm(data[fo:fo+fs], va):
    if ins.id == 0: continue
    n += 1
    if ins.mnemonic == "adrp" and len(ins.operands) >= 2:
        prev[md.reg_name(ins.operands[0].reg)] = ins.operands[1].imm & 0xFFFFFFFFFFFFFFFF
    elif ins.mnemonic == "add" and len(ins.operands) >= 3:
        if ins.operands[1].type == ARM64_OP_REG and ins.operands[2].type == ARM64_OP_IMM:
            s = md.reg_name(ins.operands[1].reg)
            if s in prev:
                t = (prev[s] + ins.operands[2].imm) & 0xFFFFFFFFFFFFFFFF
                if t in hits: hits[t].append(ins.address)
print(f"扫 AVE2 __TEXT_EXEC: {n} 条指令\n")
for k, name in targets.items():
    print(f"=== {name}  引用 {len(hits[k])} ===")
    for a in hits[k][:8]:
        print(f"  0x{a:x}")
