import struct, re
from capstone import *

P = r"E:\IOS18.7.2\work\kext\a12_18.7.2_AppleJPEGDriver"
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

# 1) 找 commandGate / IOCommandGate 相关字符串
print("=== 相关字符串 ===")
for kw in (b"commandGate", b"IOCommandGate", b"initWithTask", b"externalMethod"):
    for m in re.finditer(rb"[A-Za-z: ]{0,40}" + kw + rb"[A-Za-z_ :\(\)\*]{0,60}\x00", data):
        s = m.group()[:-1].decode("ascii","replace")
        if len(s) < 8: continue
        fva=None
        for sn,sva,svs,sfo,sfs in segs:
            if sfo <= m.start() < sfo+sfs: fva = sva+(m.start()-sfo)
        print(f"  0x{fva:x}  {s[:80]}")
        break

# 2) 找 AppleJPEGDriverUserClient 的 initWithTask：特征 = 早期 bl 到外部然后 str 到 this+偏移
print("\n=== 疑似 initWithTask / 构造链（函数内 bl 外部 + str x0,[this,#off]）===")
EX = [s for s in segs if s[0]=="__TEXT_EXEC"][0]
code = data[EX[3]:EX[3]+EX[4]]
ins_all = list(md.disasm(code, EX[1]))
# 以 pacibsp 切函数
starts = [ins.address for ins in ins_all if ins.id and ins.mnemonic=="pacibsp"]
starts.append(EX[1]+EX[2])
cands=[]
for i in range(len(starts)-1):
    a, b = starts[i], starts[i+1]
    if b-a < 0x40 or b-a > 0x400: continue
    fn = [x for x in ins_all if a <= x.address < b]
    ext_bl = []
    str_after = 0
    for j,ins in enumerate(fn):
        if ins.id==0: continue
        if ins.mnemonic=="bl" and ins.operands and ins.operands[0].type==2:
            t = ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
            if va2seg(t) is None:
                ext_bl.append((ins.address, t))
        if ins.mnemonic=="str" and ins.op_str.startswith("x0, [x"):
            str_after += 1
    if len(ext_bl) >= 2 and str_after >= 1:
        cands.append((a, b-a, ext_bl[:4]))
for a,ln,bls in cands[:15]:
    print(f"  0x{a:x}  len=0x{ln:x}  ext_bl={[hex(t) for _,t in bls]}")
