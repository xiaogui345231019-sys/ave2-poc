import struct
from capstone import *
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

P = r"E:\IOS18.7.2\work\kext\a14_18.6.2_AppleJPEGDriver"
data = open(P, "rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off = 32; segs = []; lcst = None
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        sn = data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va, vs, fo, fs = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn, va, vs, fo, fs))
    if cmd == 0x26:
        lcst = struct.unpack_from("<II", data, off+8)
    off += cmdsize

text = [s for s in segs if s[0]=="__TEXT"][0]
execs = [s for s in segs if s[0]=="__TEXT_EXEC"][0]
print(f"LC_FUNCTION_STARTS dataoff=0x{lcst[0]:x} size={lcst[1]}")

def uleb(buf, i):
    r = 0; sh = 0
    while True:
        b = buf[i]; i += 1
        r |= (b & 0x7f) << sh
        if not (b & 0x80): break
        sh += 7
    return r, i

blob = data[lcst[0]:lcst[0]+lcst[1]]
addrs = []; cur = 0; i = 0
while i < len(blob):
    d, i = uleb(blob, i)
    if d == 0: break
    cur += d; addrs.append(cur)
print(f"functions: {len(addrs)}")

funcs = []
for k, a in enumerate(addrs):
    va = text[1] + a
    nxt = (text[1] + addrs[k+1]) if k+1 < len(addrs) else (execs[1]+execs[2])
    funcs.append((va, nxt-va))
print(f"first=0x{funcs[0][0]:x} last=0x{funcs[-1][0]:x}")

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True
cands=[]
for va, sz in funcs:
    if not (0x200 <= sz <= 0x340): continue
    foff=None
    for sn,sva,svs,sfo,sfs in segs:
        if sn in ("__TEXT_EXEC","__TEXT") and sva<=va<sva+svs:
            foff=sfo+(va-sva); break
    if foff is None: continue
    code=data[foff:foff+sz]
    found=[]
    for ins in md.disasm(code, va):
        if ins.id==0: continue
        if ins.mnemonic in ("cmp","subs") and len(ins.operands)>=2:
            try:
                if ins.operands[0].type==ARM64_OP_REG and ins.operands[1].type==ARM64_OP_IMM:
                    r=ins.reg_name(ins.operands[0].reg); imm=ins.operands[1].imm
                    if r in ("w2","w3") and 0<imm<=8:
                        found.append((ins.address,r,imm))
            except Exception: pass
    if found: cands.append((va,sz,found))

print(f"\n=== candidates: {len(cands)} ===")
for va,sz,found in cands[:15]:
    print(f"  0x{va:x}  size=0x{sz:x}")
    for a,r,i in found[:5]: print(f"      0x{a:x}  cmp {r}, #{i}")
