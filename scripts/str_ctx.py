import re
KC = r"E:\IOS18.7.2\work\fw\a14_18.7.2_22H124\kernelcache.release.iphone13.raw"
data = open(KC,"rb").read()
for kw in (b"clientHasPrivilege", b"IOService::open"):
    print(f"\n=== {kw.decode()} ===")
    for i, m in enumerate(re.finditer(re.escape(kw), data)):
        if i >= 3: break
        s = max(0, m.start()-200); e = min(len(data), m.start()+260)
        frag = data[s:e]
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in frag)
        on = m.start()-s
        print(f"  0x{m.start():x} (rel {on}):")
        print(f"    ctx: {txt}")
