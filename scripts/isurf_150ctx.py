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

def va2fo(va):
    for sn,sva,svs,sfo,sfs in segs:
        if sva<=va<sva+svs and sfs: return sfo+(va-sva)
    return None
def va2seg(va):
    for sn,sva,svs,sfo,sfs in segs:
        if sva<=va<sva+svs: return sn

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True

# 14 个真读点（去掉 [sp,#0x150]）
READS = [
 0xfffffff009e6ccc0, 0xfffffff009e6f9f8, 0xfffffff009e6fa28,
 0xfffffff009e72d2c, 0xfffffff009e7bab4,
 0xfffffff009e800f0, 0xfffffff009e802f0, 0xfffffff009e8080c,
 0xfffffff009e818e4, 0xfffffff009e82bb8, 0xfffffff009e82c5c,
 0xfffffff009e82d38, 0xfffffff009e82e1c, 0xfffffff009e8354c,
]

# 已知内核函数（用于标注 bl 目标是否像 memcpy/memset）
NOTABLE = {
    0xfffffff007ec0000: "memset? (DCP 里用过做填充)",
}

for SITE in READS:
    f = va2fo(SITE)
    if f is None: continue
    # 往前找函数起点
    start = SITE
    for back in range(0,0x800,4):
        va = SITE-back
        ff = va2fo(va)
        if ff is None: break
        if data[ff:ff+4]==b"\x7f\x23\x03\xd5":
            start=va; break
    fnlen = SITE-start
    print(f"\n=== 读点 0x{SITE:x}  函数 0x{start:x} (+0x{fnlen:x}) ===")
    a = max(start, SITE-0x30)
    f2 = va2fo(a)
    cnt = 0
    for ins in md.disasm(data[f2:f2+0x90], a):
        if ins.id==0: continue
        mark = ""
        if ins.mnemonic=="bl" and ins.operands and ins.operands[0].type==2:
            t = ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
            seg_name = va2seg(t)
            if seg_name is None:
                mark = f"   → 0x{t:x} (外部)"
            elif t in NOTABLE:
                mark = f"   → {NOTABLE[t]}"
        if ins.address == SITE: mark += "   <<< 读 +0x150"
        print(f"  0x{ins.address:x}  {ins.mnemonic:9s} {ins.op_str}{mark}")
        cnt+=1
        if cnt>=26: break
