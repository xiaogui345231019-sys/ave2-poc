import struct
from capstone import *
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

P = r"E:\IOS18.7.2\work\kext\a14_18.6.2_com.apple.iokit.IOSurface"
data = open(P, "rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off=32; segs=[]
for _ in range(ncmds):
    cmd,cmdsize = struct.unpack_from("<II", data, off)
    if cmd==0x19:
        sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va,vs,fo,fs = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn,va,vs,fo,fs))
    off+=cmdsize
print("=== segments ===")
for s in segs: print(f"  {s[0]:16s} va=0x{s[1]:x} size=0x{s[2]:x} foff=0x{s[3]:x}")

def va2fo(va):
    for sn,sva,svs,sfo,sfs in segs:
        if sva<=va<sva+svs and sfs: return sfo+(va-sva)
    return None

START, LEN = 0xfffffff009e8484c, 0x534
fo = va2fo(START)
print(f"\n=== 0x9e8484c (size 0x534) fo=0x{fo:x} ===")
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True
code = data[fo:fo+LEN]

# 追踪 x1 的派生寄存器，统计从"输入指针"读取的最大偏移
ins_list = list(md.disasm(code, START))
print(f"total insns: {len(ins_list)}")

# 第 1 遍：标出所有 ldr/ldrb/ldrh/ldrsw 及其结果寄存器
reads = []
for ins in ins_list:
    if ins.id==0: continue
    if ins.mnemonic.startswith("ldr") and len(ins.operands)>=2:
        ops = ins.operands
        dst = ops[0]
        mem = ops[-1]
        if mem.type == ARM64_OP_MEM:
            reads.append((ins.address, ins.mnemonic, md.reg_name(dst.reg) if dst.type==ARM64_OP_REG else "?",
                          md.reg_name(mem.mem.base), mem.mem.disp, ins.op_str))

print("\n=== all loads (addr / insn / dst / base / disp) ===")
for a,m,d,b,disp,ops in reads:
    print(f"  0x{a:x}  {m:7s} {d:5s} <- [{b}{', #'+hex(disp) if disp else ''}]   {ops}")

# 找出最大的正偏移（说明按固定布局读多远）
disp_vals = [(disp, a) for a,m,d,b,disp,ops in reads if disp > 0]
disp_vals.sort(reverse=True)
print("\n=== top 10 largest displacements ===")
for d,a in disp_vals[:10]:
    print(f"  0x{d:x}  @0x{a:x}")
