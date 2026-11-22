import struct
from capstone import *
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

P = r"E:\IOS18.7.2\work\kext\a14_18.6.2_AppleJPEGDriver"
data = open(P, "rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off = 32; segs = []
lcstarts = None
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        sn = data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va, vs, fo, fs = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn, va, vs, fo, fs))
    if cmd == 0x26:  # LC_FUNCTION_STARTS
        lcstarts = struct.unpack_from("<II", data, off+8)
    off += cmdsize
print("LC_FUNCTION_STARTS:", lcstarts)

exec_seg = [s for s in segs if s[0]=="__TEXT_EXEC"][0]
va0, vsize, foff, fsize = exec_seg
code = data[foff:foff+fsize]

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

# 找形如  cmp w3,#N  (newUserClient 的 type 检查)  N in 1..8
hits = []
for ins in md.disasm(code, va0):
    if ins.id == 0: continue
    if ins.mnemonic in ("cmp","subs") and len(ins.operands)>=2:
        try:
            if ins.operands[0].type==ARM64_OP_REG and ins.operands[1].type==ARM64_OP_IMM:
                r = ins.reg_name(ins.operands[0].reg)
                imm = ins.operands[1].imm
                if r in ("w1","w2","w3","w4") and 0 < imm <= 8:
                    hits.append((ins.address, r, imm))
        except Exception:
            pass

print(f"\n=== cmp w1..w4, #1..8 : {len(hits)} hits ===")
for a, r, i in hits[:60]:
    print(f"  0x{a:x}  cmp {r}, #{i}")
