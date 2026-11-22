import struct
from capstone import *

P = r"E:\IOS18.7.2\work\kext\ave2_a14_18.7.2"
data = open(P, "rb").read()
magic = struct.unpack_from("<I", data, 0)[0]
ncmds = struct.unpack_from("<I", data, 16)[0]
off = 32
segs = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        segname = data[off+8:off+24].rstrip(b"\0").decode("ascii", "replace")
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((segname, vmaddr, vmsize, fileoff, filesize))
    off += cmdsize
print("=== segments ===")
for s in segs: print(f"  {s[0]:20s} va=0x{s[1]:x} size=0x{s[2]:x} foff=0x{s[3]:x} fsize=0x{s[4]:x}")

def fo2va(fo):
    for name, va, vs, foff, fsz in segs:
        if foff and foff <= fo < foff + fsz:
            return va + (fo - foff), name
    return None, None

for label, fo in (("newUserClient", 0x63981), ("AppleAVE2UserClient", 0x6194c)):
    va, seg = fo2va(fo)
    print(f"  {label}: file 0x{fo:x} -> VA {hex(va) if va else 'None'} ({seg})")

target_va, _ = fo2va(0x63981)
target2_va, _ = fo2va(0x6194c)
targets = {target_va: "newUserClient", target2_va: "AppleAVE2UserClient"}

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
for name, va, vs, foff, fsz in segs:
    if name not in ("__TEXT_EXEC", "__TEXT"): continue
    code = data[foff:foff+fsz]
    adrp_regs = {}
    for ins in md.disasm(code, va):
        if ins.id == 0: continue
        if ins.mnemonic == "adrp" and len(ins.operands) == 2 and ins.operands[0].type == ARM64_OP_REG:
            try:
                imm = ins.operands[1].imm & 0xFFFFFFFFFFFFFFFF
                adrp_regs[ins.reg_name(ins.operands[0].reg)] = (imm, ins.address)
            except Exception:
                pass
        elif ins.mnemonic == "add" and len(ins.operands) == 3:
            if ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_REG and ins.operands[2].type == ARM64_OP_IMM:
                base = ins.reg_name(ins.operands[1].reg)
                if base in adrp_regs:
                    pg, adrp_at = adrp_regs[base]
                    tgt = (pg + ins.operands[2].imm) & 0xFFFFFFFFFFFFFFFF
                    if tgt in targets:
                        print(f"  *** {targets[tgt]} ref @ 0x{ins.address:x} (adrp @ 0x{adrp_at:x})")
                        adrp_regs.pop(base, None)
