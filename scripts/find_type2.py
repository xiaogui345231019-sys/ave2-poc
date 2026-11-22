import struct
from capstone import *
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

P = r"E:\IOS18.7.2\work\kext\ave2_a14_18.7.2"
data = open(P, "rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off = 32; segs = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        segname = data[off+8:off+24].rstrip(b"\0").decode("ascii", "replace")
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((segname, vmaddr, vmsize, fileoff, filesize))
    off += cmdsize

TARGETS = {0xfffffff007292a38: "AppleAVE2Driver", 0xfffffff007292a48: "site.AppleAVE2Driver"}
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
refs = []
for name, va, vs, foff, fsz in segs:
    if name != "__TEXT_EXEC": continue
    code = data[foff:foff+fsz]
    adrp_regs = {}
    for ins in md.disasm(code, va):
        if ins.id == 0: continue
        try:
            if ins.mnemonic == "adrp" and len(ins.operands) == 2 and ins.operands[0].type == ARM64_OP_REG:
                adrp_regs[ins.reg_name(ins.operands[0].reg)] = (ins.operands[1].imm & 0xFFFFFFFFFFFFFFFF, ins.address)
            elif ins.mnemonic == "add" and len(ins.operands) == 3 \
                 and ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_REG \
                 and ins.operands[2].type == ARM64_OP_IMM:
                b = ins.reg_name(ins.operands[1].reg)
                if b in adrp_regs:
                    pg, _ = adrp_regs[b]
                    t = (pg + ins.operands[2].imm) & 0xFFFFFFFFFFFFFFFF
                    if t in TARGETS:
                        refs.append((ins.address, TARGETS[t]))
        except Exception:
            pass

print(f"=== refs to AppleAVE2Driver: {len(refs)} ===")
for a, lbl in refs[:25]:
    print(f"  0x{a:x}  {lbl}")
if refs:
    lo = min(r[0] for r in refs); hi = max(r[0] for r in refs)
    print(f"\ncluster: 0x{lo:x} .. 0x{hi:x}")
    te = [s for s in segs if s[0] == "__TEXT_EXEC"][0]
    name, va, vs, foff, fsz = te
    start = (lo - 0x200) & ~3
    length = min(hi - start + 0x600, 0x6000)
    fo_start = foff + (start - va)
    code = data[fo_start:fo_start+length]
    md2 = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    lines = [(i.address, i.mnemonic, i.op_str) for i in md2.disasm(code, start) if i.id != 0]
    print(f"=== disassembled {len(lines)} insns 0x{start:x}.. ===")
    for i, (a, m, o) in enumerate(lines):
        if m in ("cmp", "subs", "tbnz", "tbz") and ("w3," in o or "w2," in o or "w1," in o):
            print(f"--- {m} {o} @ 0x{a:x} ---")
            for j in range(max(0, i-3), min(len(lines), i+5)):
                aa, mm, oo = lines[j]
                print(f"  {'>>' if j==i else '  '} 0x{aa:x}  {mm:8s} {oo}")
