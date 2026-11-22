import struct
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

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
TARGETS = {0xe00002e2: "kIOReturnNotPermitted",
           0xe00002e3: "kIOReturnNotPrivileged",
           0xe00002c7: "kIOReturnUnsupported",
           0xe00002c9: "kIOReturnBadArgument",
           0xe00002bc: "kIOReturnError",
           0xe00002c1: "kIOReturnNotReady"}

hits = {}
for name, va, vs, foff, fsz in segs:
    if name != "__TEXT_EXEC": continue
    code = data[foff:foff+fsz]
    for ins in md.disasm(code, va):
        if ins.id == 0: continue
        try:
            if ins.mnemonic in ("mov","movz","movn","movk"):
                for op in ins.operands:
                    if op.type == 2 and op.imm in TARGETS:
                        hits.setdefault(TARGETS[op.imm], []).append((ins.address, ins.mnemonic, ins.op_str))
            elif ins.mnemonic in ("orr","add","sub","and"):
                for op in ins.operands:
                    if op.type == 2 and op.imm in TARGETS:
                        hits.setdefault(TARGETS[op.imm], []).append((ins.address, ins.mnemonic, ins.op_str))
        except Exception:
            pass

for k in TARGETS.values():
    v = hits.get(k, [])
    print(f"=== {k}: {len(v)} hits ===")
    for a, m, o in v[:25]:
        print(f"   0x{a:x}  {m:8s} {o}")
