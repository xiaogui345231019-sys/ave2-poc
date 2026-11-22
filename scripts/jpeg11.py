import struct
P = r"E:\IOS18.7.2\work\kext\a12_18.7.2_AppleJPEGDriver"
data = open(P, "rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off=32; segs={}
for _ in range(ncmds):
    cmd,cmdsize = struct.unpack_from("<II", data, off)
    if cmd==0x19:
        sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va,vs,fo,fs = struct.unpack_from("<QQQQ", data, off+24)
        segs[sn]=(va,vs,fo,fs)
    off+=cmdsize

EXEC = segs["__TEXT_EXEC"]; TEXT = segs["__TEXT"]
def in_code(v):
    return (EXEC[0] <= v < EXEC[0]+EXEC[1]) or (TEXT[0] <= v < TEXT[0]+TEXT[1])

for segname in ("__DATA_CONST","__DATA"):
    lo,sz,fo,fs = segs[segname]
    blob = data[fo:fo+fs]
    print(f"\n=== {segname}  va=0x{lo:x}  size=0x{sz:x} ===")
    # 找连续 24B 项：第一个 qword 指向代码段
    results=[]
    for start in range(0, len(blob)-24, 8):
        run=[]
        for k in range(80):
            o = start+k*24
            if o+24>len(blob): break
            q = struct.unpack_from("<Q", blob, o)[0]
            if not in_code(q): break
            ci,si,co,so = struct.unpack_from("<IIII", blob, o+8)
            if ci>8 or co>8 or si>0x200000 or so>0x200000: break
            run.append((q,ci,si,co,so))
        if len(run)>=4: results.append((start,run))
    results.sort(key=lambda x:-len(x[1]))
    seen_starts=set()
    shown=0
    for start,run in results:
        if any(abs(start-s)<24 for s in seen_starts): continue
        seen_starts.add(start)
        print(f"  --- table @ va 0x{lo+start:x}  entries={len(run)} ---")
        for i,(fn,ci,si,co,so) in enumerate(run[:40]):
            print(f"      idx {i:2d} fn=0x{fn:x} in(s={ci},st=0x{si:x}) out(s={co},st=0x{so:x})")
        shown+=1
        if shown>=3: break
    if shown==0: print("  (none)")
