import struct
FIX = 0xfffffff007004000
THUNK = 0xfffffff009cecf8c        # ldr x0,[x0,#0x140]; b backing
TARGETS = {THUNK: "surface-fill thunk", 0xfffffff009cec5e0: "backing+memset"}

KEYS = [
    ("IOMobileGraphicsFamily",     r"E:\IOS18.7.2\work\kext\a14_18.7.2_IOMobileGraphicsFamily"),
    ("IOMobileGraphicsFamily-DCP", r"E:\IOS18.7.2\work\kext\a14_18.7.2_IOMobileGraphicsFamily-DCP"),
    ("AppleMobileDispH13P-DCP",    r"E:\IOS18.7.2\work\kext\a14_18.7.2_AppleMobileDispH13P-DCP"),
]

KNOWN_VT = {
    0xfffffff007c687b8: "UnifiedPipeline2",
    0xfffffff007c69380: "AppleCLCD2",
    0xfffffff007c69b18: "AppleCLCD2.sub",
    0xfffffff007c69f78: "IOMobileFramebufferShim",
}

def load(P):
    d = open(P,"rb").read()
    n = struct.unpack_from("<I", d, 16)[0]
    off=32; segs=[]
    for _ in range(n):
        cmd,cs = struct.unpack_from("<II", d, off)
        if cmd==0x19:
            sn=d[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
            va,vs,fo,fs = struct.unpack_from("<QQQQ", d, off+24)
            segs.append((sn,va,vs,fo,fs))
        off+=cs
    return d, segs

print("=== 谁的 __DATA_CONST 指向这个 thunk ===")
for label,P in KEYS:
    d,s = load(P)
    for sn,sva,svs,sfo,sfs in s:
        if sn!="__DATA_CONST": continue
        blob = d[sfo:sfo+sfs]
        for o in range(0,len(blob)-8,8):
            q = struct.unpack_from("<Q", blob, o)[0]
            if q==0: continue
            v = FIX + (q & 0xFFFFFFFF)
            if v in TARGETS:
                slot = sva+o
                # 尝试归属到已知 vtable 基址
                owner = ""
                for vbase, name in KNOWN_VT.items():
                    if vbase <= slot < vbase+0x1200:
                        owner = f"  → {name} 的 +0x{slot-vbase:x} 槽"
                        break
                print(f"  [{label}] slot 0x{slot:x} -> 0x{v:x} ({TARGETS[v]}){owner}")
