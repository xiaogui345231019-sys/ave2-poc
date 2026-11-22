import struct
from capstone import *
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

for label, P in (("A14/18.6.2", r"E:\IOS18.7.2\work\kext\a14_18.6.2_AppleJPEGDriver"),
                 ("A12/18.7.2", r"E:\IOS18.7.2\work\kext\a12_18.7.2_AppleJPEGDriver")):
    data = open(P, "rb").read()
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off=32; segs=[]; lcst=None
    for _ in range(ncmds):
        cmd,cmdsize = struct.unpack_from("<II", data, off)
        if cmd==0x19:
            sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
            va,vs,fo,fs=struct.unpack_from("<QQQQ", data, off+24)
            segs.append((sn,va,vs,fo,fs))
        if cmd==0x26: lcst=struct.unpack_from("<II", data, off+8)
        off+=cmdsize
    text=[s for s in segs if s[0]=="__TEXT"][0]
    execs=[s for s in segs if s[0]=="__TEXT_EXEC"][0]

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

    md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True
    print(f"\n=== {label}: searching 0xe00002c2 (NotAttached) ===")
    found=0
    for va,sz in funcs:
        foff=None
        for sn,sva,svs,sfo,sfs in segs:
            if sn in ("__TEXT_EXEC","__TEXT") and sva<=va<sva+svs:
                foff=sfo+(va-sva);break
        if foff is None: continue
        code=data[foff:foff+sz]
        hits=[]
        for ins in md.disasm(code, va):
            if ins.id==0: continue
            try:
                for op in ins.operands:
                    if op.type==ARM64_OP_IMM and op.imm==0xe00002c2:
                        hits.append((ins.address, ins.mnemonic, ins.op_str))
            except Exception: pass
        if hits:
            print(f"  func 0x{va:x} size=0x{sz:x}")
            for a,m,o in hits[:4]:
                print(f"      0x{a:x}  {m:8s} {o}")
            found+=1
    if not found: print("  (0xe00002c2 not found as immediate)")
