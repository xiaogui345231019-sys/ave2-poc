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
        v,sz,f,s = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn,v,sz,f,s))
    off+=cs
sn,va,vs,fo,fs = [s for s in segs if s[0]=="__TEXT_EXEC"][0]
code = data[fo:fo+fs]

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
md.skipdata = True

# ---- 第一遍：流式找 [x?,#0xdc] 的 load，记录 (addr, base_reg, dst_reg) ----
loads = []
for ins in md.disasm(code, va):
    if ins.id == 0: continue
    if ins.mnemonic not in ("ldr","ldur"): continue
    ops = ins.operands
    if len(ops) < 2: continue
    if ops[0].type != ARM64_OP_REG: continue
    mem = ops[-1]
    if mem.type != ARM64_OP_MEM or mem.mem.disp != 0xdc: continue
    loads.append((ins.address, md.reg_name(mem.mem.base), md.reg_name(ops[0].reg)))
print(f"[pass1] [x?,#0xdc] load: {len(loads)} 处")

# ---- 第二遍：对每个候选，反汇编该处往后 0x20 字节，检查 add#1 + str 同 disp ----
def dis_at(addr, n=0x20):
    o = fo + (addr - va)
    return list(md.disasm(data[o:o+n], addr))

inc = []
for addr, base, dreg in loads:
    seq = dis_at(addr, 0x1c)
    has_add = has_str = False
    for ins in seq[1:]:
        if ins.id == 0: continue
        if ins.mnemonic in ("add","adds") and len(ins.operands)>=3:
            if (ins.operands[0].type==ARM64_OP_REG and md.reg_name(ins.operands[0].reg)==dreg
                and ins.operands[1].type==ARM64_OP_REG and md.reg_name(ins.operands[1].reg)==dreg
                and ins.operands[2].type==ARM64_OP_IMM and ins.operands[2].imm==1):
                has_add = True
        if ins.mnemonic in ("str","stur") and len(ins.operands)>=2:
            m = ins.operands[-1]
            if m.type==ARM64_OP_MEM and m.mem.disp==0xdc and md.reg_name(m.mem.base)==base:
                if ins.operands[0].type==ARM64_OP_REG and md.reg_name(ins.operands[0].reg)==dreg:
                    has_str = True
    if has_add and has_str:
        inc.append((addr, base, dreg))

print(f"\n=== timestamp++ 形态: {len(inc)} 处 ===")
for a,b,r in inc:
    print(f"  0x{a:x}  base={b}  reg={r}")

# ---- 把这些地址归属到函数（找最近的 pacibsp） ----
print("\n=== 归属函数 ===")
def func_start(addr):
    # 往前最多 0x800 找 pacibsp
    for back in range(0, 0x800, 4):
        a = addr - back
        o = fo + (a - va)
        if o < 0: break
        if data[o:o+4] == b"\x7f\x23\x03\xd5":
            return a
    return addr
seen = {}
for a,b,r in inc:
    fs_ = func_start(a)
    seen.setdefault(fs_, []).append(a)
for f_, lst in sorted(seen.items()):
    print(f"  func 0x{f_:x}  ({len(lst)} 个 timestamp++ 站点)")
