import struct
from capstone import *
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

P = r"E:\IOS18.7.2\work\kext\a14_18.6.2_AppleJPEGDriver"
data = open(P, "rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off=32; segs=[]; lcst=None
for _ in range(ncmds):
    cmd,cmdsize = struct.unpack_from("<II", data, off)
    if cmd==0x19:
        sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va,vs,fo,fs = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn,va,vs,fo,fs))
    if cmd==0x26: lcst=struct.unpack_from("<II", data, off+8)
    off+=cmdsize

text=[s for s in segs if s[0]=="__TEXT"][0]
execs=[s for s in segs if s[0]=="__TEXT_EXEC"][0]
dc=[s for s in segs if s[0]=="__DATA_CONST"][0]
dt=[s for s in segs if s[0]=="__DATA"][0]

def uleb(b,i):
    r=0;sh=0
    while True:
        x=b[i];i+=1
        r|=(x&0x7f)<<sh
        if not (x&0x80):break
        sh+=7
    return r,i

blob=data[lcst[0]:lcst[0]+lcst[1]]
addrs=[];cur=0;i=0
while i<len(blob):
    d,i=uleb(blob,i)
    if d==0:break
    cur+=d;addrs.append(cur)
funcs=[]
for k,a in enumerate(addrs):
    va=text[1]+a
    nxt=(text[1]+addrs[k+1]) if k+1<len(addrs) else (execs[1]+execs[2])
    funcs.append((va,nxt-va))

# 找 dispatcher：函数内 adrp+add 指向 data 段（表），且函数含 cmp w1, #N
md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True
print("=== functions referencing __DATA_CONST/__DATA with cmp w1,#N ===")
for va,sz in funcs:
    foff=None
    for sn,sva,svs,sfo,sfs in segs:
        if sn in ("__TEXT_EXEC","__TEXT") and sva<=va<sva+svs:
            foff=sfo+(va-sva);break
    if foff is None: continue
    code=data[foff:foff+sz]
    regs={}; tblref=[]; cmps=[]
    for ins in md.disasm(code, va):
        if ins.id==0: continue
        try:
            if ins.mnemonic=="adrp" and len(ins.operands)==2 and ins.operands[0].type==ARM64_OP_REG:
                regs[ins.reg_name(ins.operands[0].reg)]=(ins.operands[1].imm & 0xFFFFFFFFFFFFFFFF, ins.address)
            elif ins.mnemonic=="add" and len(ins.operands)==3 and ins.operands[0].type==ARM64_OP_REG and ins.operands[1].type==ARM64_OP_REG and ins.operands[2].type==ARM64_OP_IMM:
                b=ins.reg_name(ins.operands[1].reg)
                if b in regs:
                    pg,_=regs[b]; t=(pg+ins.operands[2].imm)&0xFFFFFFFFFFFFFFFF
                    if dc[1]<=t<dc[1]+dc[2] or dt[1]<=t<dt[1]+dt[2]:
                        tblref.append((ins.address,t))
                    regs.pop(b,None)
            elif ins.mnemonic in ("cmp","subs") and len(ins.operands)>=2:
                if ins.operands[0].type==ARM64_OP_REG and ins.operands[1].type==ARM64_OP_IMM:
                    if ins.reg_name(ins.operands[0].reg)=="w1" and ins.operands[1].imm>1:
                        cmps.append((ins.address, ins.operands[1].imm))
        except Exception: pass
    if tblref and cmps:
        print(f"\n  0x{va:x} size=0x{sz:x}")
        for a,t in tblref[:4]: print(f"      table ref @0x{a:x} -> 0x{t:x}")
        for a,i_ in cmps[:4]: print(f"      cmp w1,#{i_} @0x{a:x}")
