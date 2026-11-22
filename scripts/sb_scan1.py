import struct, re
KC = r"E:\IOS18.7.2\work\fw\a14_18.7.2_22H124\kernelcache.release.iphone13.raw"
data = open(KC,"rb").read()
print(f"KC = {len(data)} bytes")

# 1) 找所有 strings 段里的 sandbox 相关
pats = [b"com.apple.security.sandbox", b"Sandbox.kext", b"iokit-open", b"IOKit", b"iokit-user-client-class",
        b"AppleAVE2", b"ave2", b"profile", b".sb", b"seatbelt", b"mac_iokit"]
print("\n=== 关键字符串出现次数 ===")
for p in pats:
    n = data.count(p)
    print(f"  {p.decode(errors='replace'):32s} {n}")

# 2) 定位 com.apple.security.sandbox 上下文
print("\n=== com.apple.security.sandbox 上下文（最多 3 处）===")
for i, m in enumerate(re.finditer(rb"com\.apple\.security\.sandbox", data)):
    if i >= 3: break
    s = max(0, m.start()-80); e = min(len(data), m.start()+160)
    frag = data[s:e]
    txt = "".join(chr(c) if 32 <= c < 127 else "." for c in frag)
    print(f"  0x{m.start():x}: {txt}")

# 3) 找 iokit-open 的规则串
print("\n=== iokit-open / iokit-user-client-class 上下文 ===")
for kw in (b"iokit-open", b"iokit-user-client-class"):
    for i, m in enumerate(re.finditer(re.escape(kw), data)):
        if i >= 4: break
        s = max(0, m.start()-100); e = min(len(data), m.start()+180)
        frag = data[s:e]
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in frag)
        print(f"  [{kw.decode()}] 0x{m.start():x}: {txt}")
