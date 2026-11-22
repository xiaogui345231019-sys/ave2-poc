import struct, sys
from capstone import *

P = r"E:\IOS18.7.2\work\kext\a14_18.6.2_AppleJPEGDriver"
data = open(P, "rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off = 32; segs = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        sn = data[off+8:off+24].rstrip(b"\0").decode("ascii","replace")
        va, vs, fo, fs = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((sn, va, vs, fo, fs))
    off += cmdsize
print("=== AppleJPEGDriver (A14/18.6.2) segments ===")
for s in segs: print(f"  {s[0]:18s} va=0x{s[1]:x} size=0x{s[2]:x} foff=0x{s[3]:x} fsize=0x{s[4]:x}")

# 1) strings related to external method / selectors
import re
print("\n=== cstring hits (Method/Selector/dispatch) ===")
for m in re.finditer(rb"[ -~]{6,}", data):
    s = m.group().decode("ascii","replace")
    if any(k in s for k in ("externalMethod","ExternalMethod","scalarInput","structureInput","Selector","selector","Dispatch")):
        print(f"  0x{m.start():08x}  {s[:100]}")
