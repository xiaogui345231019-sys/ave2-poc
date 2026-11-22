import re
P = r"C:\Users\Administrator\AppData\Local\Sideloadly\sideloadly.exe"
data = open(P, "rb").read()
print(f"size = {len(data)}")
kw = [b"listdir", b"Apple Application Support", b"Common Files", b"MobileDevice.dll",
      b"iTunes", b"Program Files", b"AppleMobileDevice"]
for k in kw:
    idxs = [m.start() for m in re.finditer(re.escape(k), data)]
    print(f"\n=== {k.decode()} : {len(idxs)} hits ===")
    for i in idxs[:6]:
        s = max(0, i-80); e = min(len(data), i+120)
        frag = data[s:e]
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in frag)
        print(f"  0x{i:08x}: {txt}")
