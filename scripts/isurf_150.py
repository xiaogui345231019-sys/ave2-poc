import struct
from capstone import *

P = r"E:\IOS18.7.2\work\kext\a14_18.7.2_com.apple.iokit.IOSurface"
data = open(P,"rb").read()
n = struct.unpack_from("<I", data, 16)[0]
off=32; segs=[]
for _ in range(n):
    cmd,cs = struct.unpack_from("<II", data, off)
    if cmd==0x19:
        sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va,vs,fo,fs = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn,va,vs,fo,fs))
    off+=cs

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True

print("=== IOSurface+0x150 的全部访问点 ===")
reads, writes = [], []
for sn,sva,svs,sfo,sfs in segs:
    if sn not in ("__TEXT_EXEC","__TEXT"): continue
    for ins in md.disasm(data[sfo:sfo+sfs], sva):
        if ins.id==0: continue
        if "#0x150" in ins.op_str and ins.mnemonic in ("ldr","str","ldur","stur","ldp","stp"):
            (reads if ins.mnemonic.startswith("ld") else writes).append((ins.address, ins.mnemonic, ins.op_str))

print(f"\n--- 读（{len(reads)}）---")
for a,m,o in reads[:25]: print(f"  0x{a:x}  {m:6s} {o}")
print(f"\n--- 写（{len(writes)}）---")
for a,m,o in writes[:25]: print(f"  0x{a:x}  {m:6s} {o}")

# 关键：看 +0x150 的 getter 0x9e6e97c 被谁调（如果存在）
print("\n=== +0x150 的 getter 候选 & 其调用者 ===")
# 先确认 getter 形态
import re
for sn,sva,svs,sfo,sfs in segs:
    if sn!="__TEXT_EXEC": continue
    il = list(md.disasm(data[sfo:sfo+sfs], sva))
    for i,ins in enumerate(il[:-1]):
        if ins.id==0: continue
        if ins.mnemonic=="ldr" and ins.op_str=="x0, [x0, #0x150]":
            nxt = il[i+1]
            if nxt.id and nxt.mnemonic in ("ret","retab"):
                gva = ins.address
                print(f"  getter 0x{gva:x}")
                # 找调用者
                for sn2,sva2,svs2,sfo2,sfs2 in segs:
                    if sn2!="__TEXT_EXEC": continue
                    for ins2 in md.disasm(data[sfo2:sfo2+sfs2], sva2):
                        if ins2.id==0: continue
                        if ins2.mnemonic=="bl" and ins2.op_str and f"0x{gva:x}" in ins2.op_str:
                            print(f"     caller 0x{ins2.address:x}")
