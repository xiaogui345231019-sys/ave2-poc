import re, os
for P in (r"C:\Users\Administrator\AppData\Local\Sideloadly\sideloadly.dll",
          r"C:\Users\Administrator\AppData\Local\Sideloadly\sideloadlydaemon.exe"):
    if not os.path.exists(P): continue
    data = open(P, "rb").read()
    print(f"\n=== {os.path.basename(P)} ({len(data)} bytes) ===")
    for kw in (b"listdir", b"Can't listdir", b"workdir", b"Apple Application Support", b"redist"):
        idxs = [m.start() for m in re.finditer(re.escape(kw), data)]
        print(f"  {kw.decode():28s} {len(idxs)} hits")
        for i in idxs[:3]:
            frag = data[max(0,i-120):i+200]
            txt = "".join(chr(c) if 32 <= c < 127 else "." for c in frag)
            print(f"    0x{i:08x}: {txt}")
