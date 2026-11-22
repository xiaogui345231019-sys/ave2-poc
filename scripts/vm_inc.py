import struct
from capstone import *
from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG, ARM64_OP_IMM

KC = r"E:\IOS18.7.2\work\fw\a14_18.7.2_22H124\kernelcache.release.iphone13.raw"
data = open(KC,"rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off=32; segs=[]
for _ in range(ncmds):
    cmd,cs = struct.unpack_from("<II", data, off)
    if cmd==0x19:
        sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va,vs,fo,fs = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn,va,vs,fo,fs))
    off+=cs
sn,va,vs,fo,fs = [s for s in segs if s[0]=="__TEXT_EXEC"][0]

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
md.skipdata = True

# 收集所有 [x?,#0xdc] 的读，然后在后续 6 条指令里找 add #1 与 str 同 disp
ins_all = list(md.disasm(data[fo:fo+fs], va))
print(f"总指令 {len(ins_all)}")

inc_sites = []   # (addr, reg, kind)
for i, ins in enumerate(ins_all):
    if ins.id == 0: continue
    # 找 ldr wN, [xM, #0xdc]
    if ins.mnemonic not in ("ldr","ldur"): continue
    ops = ins.operands
    if len(ops) < 2: continue
    dst = ops[0]; mem = ops[-1]
    if dst.type != ARM64_OP_REG or mem.type != ARM64_OP_MEM: continue
    if mem.mem.disp != 0xdc: continue
    base = md.reg_name(mem.mem.base)
    dreg = md.reg_name(dst.reg)
    # 往后 6 条内找 add dreg, dreg, #1 和 str dreg, [base, #0xdc]
    has_add = False; has_str = False
    for j in range(i+1, min(i+7, len(ins_all))):
        n = ins_all[j]
        if n.id == 0: continue
        if n.mnemonic in ("add","adds") and len(n.operands)>=3:
            if md.reg_name(n.operands[0].reg)==dreg and md.reg_name(n.operands[1].reg)==dreg:
                if n.operands[2].type==ARM64_OP_IMM and n.operands[2].imm==1:
                    has_add = True
        if n.mnemonic in ("str","stur"):
            if len(n.operands)>=2 and n.operands[-1].type==ARM64_OP_MEM:
                if n.operands[-1].mem.disp==0xdc and md.reg_name(n.operands[0].reg)==dreg:
                    has_str = True
    if has_add and has_str:
        inc_sites.append((ins.address, base, dreg))

print(f"\n=== timestamp++ 形态（ldr+add#1+str 同 disp）: {len(inc_sites)} 处 ===")
for a,b,r in inc_sites[:40]:
    print(f"  0x{a:x}  base={b} reg={r}")
