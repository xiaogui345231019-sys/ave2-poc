import struct, re
from capstone import *
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

P = r"E:\IOS18.7.2\work\kext\a14_18.6.2_AppleJPEGDriver"
data = open(P, "rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off = 32; segs = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        sn = data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va, vs, fo, fs = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn, va, vs, fo, fs))
    off += cmdsize

def fo2va(fo):
    for sn, va, vs, fo0, fs in segs:
        if fo0 <= fo < fo0+fs and fs:
            return va + (fo-fo0), sn
    return None, None

# 1) find "newUserClient" cstring in this kext
tgt = {}
for m in re.finditer(rb"newUserClient", data):
    va, sn = fo2va(m.start())
    if va: tgt[va] = "newUserClient"
    print(f"  string 'newUserClient' @ file 0x{m.start():x} -> VA 0x{va:x} ({sn})")
# also the class names
for m in re.finditer(rb"AppleJPEGDriverUserClient", data):
    va, sn = fo2va(m.start())
    print(f"  string 'AppleJPEGDriverUserClient' @ VA 0x{va:x} ({sn})")
for m in re.finditer(rb"AppleJPEGDriver\b", data):
    va, sn = fo2va(m.start())
    print(f"  string 'AppleJPEGDriver' @ VA 0x{va:x} ({sn})")

print("\n=== xref scan for those strings ===")
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
for sn, va, vs, fo0, fs in segs:
    if sn not in ("__TEXT_EXEC","__TEXT"): continue
    code = data[fo0:fo0+fs]
    regs = {}
    for ins in md.disasm(code, va):
        if ins.id == 0: continue
        try:
            if ins.mnemonic == "adrp" and len(ins.operands)==2 and ins.operands[0].type==ARM64_OP_REG:
                regs[ins.reg_name(ins.operands[0].reg)] = (ins.operands[1].imm & 0xFFFFFFFFFFFFFFFF, ins.address)
            elif ins.mnemonic == "add" and len(ins.operands)==3 and ins.operands[0].type==ARM64_OP_REG and ins.operands[1].type==ARM64_OP_REG and ins.operands[2].type==ARM64_OP_IMM:
                b = ins.reg_name(ins.operands[1].reg)
                if b in regs:
                    pg,_ = regs[b]
                    t = (pg + ins.operands[2].imm) & 0xFFFFFFFFFFFFFFFF
                    if t in tgt:
                        print(f"  *** {tgt[t]} ref @ 0x{ins.address:x}")
                        regs.pop(b, None)
        except Exception:
            pass
