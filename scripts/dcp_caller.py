import struct
from capstone import *
from capstone.arm64 import ARM64_OP_IMM

TARGET_FN = 0xfffffff009cec5e0   # 从 backing 取基址并 memset 的那段
KEYS = [
    ("IOMobileGraphicsFamily-DCP", r"E:\IOS18.7.2\work\kext\a14_18.7.2_IOMobileGraphicsFamily-DCP"),
    ("AppleMobileDispH13P-DCP",    r"E:\IOS18.7.2\work\kext\a14_18.7.2_AppleMobileDispH13P-DCP"),
    ("IOMobileGraphicsFamily",     r"E:\IOS18.7.2\work\kext\a14_18.7.2_IOMobileGraphicsFamily"),
]

def load(P):
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
    return data, segs

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail=True
all_callers = []
for label, P in KEYS:
    data, segs = load(P)
    for sn,va,vs,fo,fs in segs:
        if sn != "__TEXT_EXEC": continue
        for ins in md.disasm(data[fo:fo+fs], va):
            if ins.id==0: continue
            if ins.mnemonic=="bl" and len(ins.operands)==1 and ins.operands[0].type==ARM64_OP_IMM:
                t = ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
                if t == TARGET_FN:
                    all_callers.append((label, ins.address))
            # 也看 b（尾调）
            elif ins.mnemonic=="b" and len(ins.operands)==1 and ins.operands[0].type==ARM64_OP_IMM:
                t = ins.operands[0].imm & 0xFFFFFFFFFFFFFFFF
                if t == TARGET_FN:
                    all_callers.append((label+"/tail", ins.address))

print(f"=== bl/b 到 0x9cec5e0 的调用点: {len(all_callers)} ===")
for label, a in all_callers:
    print(f"  [{label}] 0x{a:x}")

# 已知 4 个 selector handler（子代理给的 peer vtable 槽）
KNOWN = {
    0xfffffff009cef3b8: "sel 0x4e (+0x710)",
    0xfffffff009cef5b0: "sel 0x4f (+0x718)",
    0xfffffff009cef724: "sel 0x55 (+0x720)",
    0xfffffff009cefaa0: "sel 0x44 (+0x738)",
}
print("\n=== 这些调用点是否落在 4 个已知 handler 内 ===")
for label, a in all_callers:
    for hv, name in KNOWN.items():
        if hv <= a < hv + 0x400:
            print(f"  ★ 0x{a:x} 在 {name} (0x{hv:x}) 内，偏移 +0x{a-hv:x}")
