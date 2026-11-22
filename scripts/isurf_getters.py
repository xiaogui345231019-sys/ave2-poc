import struct
from capstone import *
from capstone.arm64 import ARM64_OP_IMM

P = r"E:\IOS18.7.2\work\kext\a14_18.6.2_com.apple.iokit.IOSurface"
data = open(P,"rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off=32; segs=[]
for _ in range(ncmds):
    cmd,cmdsize = struct.unpack_from("<II", data, off)
    if cmd==0x19:
        sn=data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va,vs,fo,fs = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn,va,vs,fo,fs))
    off+=cmdsize

def va2fo(va):
    for sn,sva,svs,sfo,sfs in segs:
        if sva<=va<sva+svs and sfs: return sfo+(va-sva)
    return None

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True

# 1) 0x9e72ba4 = ldr x0,[x0,#0x30]; ret  —— 取 backing 描述符
print("=== 0x9e72ba4 (取 *(IOSurface+0x30)) ===")
fo = va2fo(0xfffffff009e72ba4)
for ins in md.disasm(data[fo:fo+0x10], 0xfffffff009e72ba4):
    if ins.id: print(f"  0x{ins.address:x}  {ins.mnemonic:8s} {ins.op_str}")

# 2) 找 IOSurfaceGetBaseAddress —— 公开 API，会读某个字段后返回
#    在 IOSurface kext 的 __TEXT_EXEC 里找形态: ldr x0,[x0,#imm]; ret
print("\n=== 搜索形如 'ldr x0,[x0,#imm]; ret' 的 getter (可能是 GetBaseAddress) ===")
EX = [s for s in segs if s[0]=="__TEXT_EXEC"][0]
code = data[EX[3]:EX[3]+EX[4]]
ins_list = list(md.disasm(code, EX[1]))
for i, ins in enumerate(ins_list[:-1]):
    if ins.id==0: continue
    if ins.mnemonic=="ldr" and ins.op_str.startswith("x0, [x0"):
        nxt = ins_list[i+1]
        if nxt.id and nxt.mnemonic=="ret":
            print(f"  0x{ins.address:x}  {ins.op_str}  ; ret")

# 3) 0x9e72cec / 0x9e792b4 / 0x9e72ed0 —— DCP 里用到的几个 IOSurface getter
print("\n=== DCP 用到的几个 IOSurface getter ===")
for a in (0xfffffff009e72cec, 0xfffffff009e792b4, 0xfffffff009e72ed0, 0xfffffff009e72c80, 0xfffffff009e72cf8):
    f = va2fo(a)
    if f is None: 
        print(f"  0x{a:x}  (不在本 kext)")
        continue
    print(f"  --- 0x{a:x} ---")
    n=0
    for ins in md.disasm(data[f:f+0x30], a):
        if ins.id==0: continue
        print(f"      0x{ins.address:x}  {ins.mnemonic:8s} {ins.op_str}")
        n+=1
        if ins.mnemonic=="ret": break
