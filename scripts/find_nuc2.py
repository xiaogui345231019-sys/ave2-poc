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

def fo2va(fo):
    for name, va, vs, foff, fsz in segs:
        if fo >= foff and fo < foff + fsz and fsz:
            return va + (fo - foff), name
    return None, None

targets = {}
for label, fo in (("newUserClient", 0x63981), ("AppleAVE2UserClient", 0x6194c), ("site.AppleAVE2UserClient", 0x61960)):
    va, seg = fo2va(fo)
    print(f"  {label:26s} file 0x{fo:x} -> VA {hex(va) if va else 'None'} ({seg})")
    if va: targets[va] = label

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
print("=== scanning for adrp+add references ===")
for name, va, vs, foff, fsz in segs:
    if name not in ("__TEXT_EXEC", "__TEXT"): continue
    code = data[foff:foff+fsz]
    adrp_regs = {}
    for ins in md.disasm(code, va):
        if ins.id == 0: continue
        try:
            if ins.mnemonic == "adrp" and len(ins.operands) == 2 and ins.operands[0].type == ARM64_OP_REG:
                pg = ins.operands[1].imm & 0xFFFFFFFFFFFFFFFF
                adrp_regs[ins.reg_name(ins.operands[0].reg)] = (pg, ins.address)
            elif ins.mnemonic == "add" and len(ins.operands) == 3 \
                 and ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_REG \
                 and ins.operands[2].type == ARM64_OP_IMM:
                base = ins.reg_name(ins.operands[1].reg)
                if base in adrp_regs:
                    pg, adrp_at = adrp_regs[base]
                    tgt = (pg + ins.operands[2].imm) & 0xFFFFFFFFFFFFFFFF
                    if tgt in targets:
                        print(f"  *** {targets[tgt]:26s} ref @ 0x{ins.address:x}  (adrp @ 0x{adrp_at:x})")
                        adrp_regs.pop(base, None)
        except Exception:
            pass
