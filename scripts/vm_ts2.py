import struct
from capstone import *
from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG

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
print(f"__TEXT_EXEC va=0x{va:x} size=0x{vs:x} filesize=0x{fs:x}")

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
md.skipdata = True

# 先看前 20 条指令解析是否正常
code = data[fo:fo+fs]
cnt = 0
print("\n=== 前 10 条（确认反汇编正常）===")
for ins in md.disasm(code[:0x40], va):
    print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}")
    cnt += 1
    if cnt >= 10: break

# 统计所有 MEM 偏移的分布，用来确认 detail 生效
print("\n=== 统计含 #0xd8 / #0xdc / #0xe0 的指令 ===")
targets = {0xd8:"0xd8", 0xdc:"0xdc", 0xe0:"0xe0", 0x30:"0x30"}
counts = {k:0 for k in targets}
samples = {k:[] for k in targets}
total = 0
for ins in md.disasm(code, va):
    total += 1
    if ins.id == 0: continue
    for op in ins.operands:
        if op.type == ARM64_OP_MEM and op.mem.disp in counts:
            counts[op.mem.disp] += 1
            if len(samples[op.mem.disp]) < 8:
                samples[op.mem.disp].append((ins.address, ins.mnemonic, ins.op_str))
print(f"总指令数(含skipdata): {total}")
for k in sorted(targets):
    print(f"  disp=0x{k:x}: {counts[k]} 处")
    for a,m,o in samples[k]:
        print(f"      0x{a:x}  {m:7s} {o}")
