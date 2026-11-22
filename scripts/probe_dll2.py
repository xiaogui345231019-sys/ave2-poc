import re, zipfile, io, os
P = r"C:\Users\Administrator\AppData\Local\Sideloadly\sideloadly.dll"
data = open(P, "rb").read()
print(f"dll size = {len(data)}")
# find embedded zip / zlib streams
zips = [m.start() for m in re.finditer(b"PK\x03\x04", data)]
print(f"PK\\x03\\x04 offsets: {len(zips)} -> {zips[:10]}")
# look for the module names in plain or compressed form
for kw in (b"impact", b"wrap.py", b"isign"):
    idxs = [m.start() for m in re.finditer(re.escape(kw), data)]
    print(f"  {kw.decode():10s} {len(idxs)} hits {idxs[:5]}")
# try each zip offset
for off in zips[:5]:
    try:
        bio = io.BytesIO(data[off:])
        z = zipfile.ZipFile(bio)
        names = z.namelist()
        print(f"\nZIP @0x{off:x}: {len(names)} members")
        for n in names[:20]: print("   ", n)
        break
    except Exception as e:
        print(f"  zip @0x{off:x} failed: {e}")
