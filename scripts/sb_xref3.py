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

targets = {
    0xfffffff0079544b4: "iokit-open*",
    0xfffffff0077b3da2: "user-client-class msg",
    0xfffffff0077bab1a: "ENTITLEMENT:exception...",
    0xfffffff0077bab43: "ENTITLEMENT:iokit-user-client-class",
}
# PRELINK_TEXT + TEXT_EXEC 都扫
scan_segs = [s for s in segs if s[0] in ("__PRELINK_TEXT","__TEXT_EXEC")]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True; md.skipdata=True

allhits = {k: [] for k in targets}
for sn,va,vs,fo,fs in scan_segs:
    prev = {}
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
                    if t in allhits:
                        allhits[t].append((sn, ins.address))
    print(f"扫 {sn}: 0x{va:x}+0x{fs:x} -> {n} 条")

for k, name in targets.items():
    print(f"\n=== {name} 0x{k:x}  引用 {len(allhits[k])} ===")
    for sn, a in allhits[k][:10]:
        print(f"  [{sn}] 0x{a:x}")
