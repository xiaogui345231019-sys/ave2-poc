import struct, re
from capstone import *

P = r"E:\IOS18.7.2\work\kext\ave2_a14_18.7.2"
data = open(P, "rb").read()
ncmds = struct.unpack_from("<I", data, 16)[0]
off = 32; segs = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        segname = data[off+8:off+24].rstrip(b"\0").decode("ascii", "replace")
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off+24)
        segs.append((segname, vmaddr, vmsize, fileoff, filesize))
    off += cmdsize

# find "AppleAVE2Driver" string
hits = [(m.start(), m.group()) for m in re.finditer(rb"[ -~]{8,}", data) if b"AppleAVE2Driver" in m.group()]
print("=== AppleAVE2Driver strings ===")
for fo, s in hits:
    for name, va, vs, foff, fsz in segs:
        if fo >= foff and fo < foff + fsz and fsz:
            print(f"  file 0x{fo:x} -> VA 0x{va + (fo-foff):x} in {name}  {s[:60]}")
            break

# disassemble the AppleAVE2UserClient method cluster and hunt cmp w3,#N
te = [s for s in segs if s[0] == "__TEXT_EXEC"][0]
name, va, vs, foff, fsz = te
start = 0xfffffff008a4b000
length = 0x2800
fo_start = foff + (start - va)
code = data[fo_start:fo_start+length]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
lines = []
for ins in md.disasm(code, start):
    if ins.id == 0: continue
    lines.append((ins.address, ins.mnemonic, ins.op_str))
print(f"=== disassembled {len(lines)} insns from 0x{start:x} ===")
for i, (addr, mn, ops) in enumerate(lines):
    if mn == "cmp" and ops.startswith("w3,"):
        print(f"--- context @ 0x{addr:x}: cmp w3, {ops.split(',')[1].strip()} ---")
        for j in range(max(0, i-4), min(len(lines), i+6)):
            a, m, o = lines[j]
            mark = ">>" if j == i else "  "
            print(f"  {mark} 0x{a:x}  {m:8s} {o}")
