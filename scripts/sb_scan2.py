KC = r"E:\IOS18.7.2\work\fw\a14_18.7.2_22H124\kernelcache.release.iphone13.raw"
data = open(KC,"rb").read()

def cstr_at(off, limit=400):
    e = off
    while e < len(data) and data[e] != 0 and e - off < limit:
        e += 1
    return data[off:e].decode("utf-8","replace")

print("=== A) iokit-user-client-class entitlement 类名表（0x7afda2 起）===")
off = 0x7afda2
# 先打印那段提示语，然后逐条打印 NUL 分隔串
for i in range(40):
    s = cstr_at(off)
    if not s:
        off += 1
        if i > 3: break
        continue
    print(f"  0x{off:x}  {s}")
    off += len(s) + 1
    if off > 0x7b0000: break

print("\n=== B) 0x7b6b43 附近（ENTITLEMENT: 前缀串）===")
off = 0x7b6ac0
for i in range(24):
    s = cstr_at(off)
    if s:
        print(f"  0x{off:x}  {s}")
        off += len(s) + 1
    else:
        off += 1

print("\n=== C) iokit-open operation 表（0x950400 附近，看前后完整表）===")
print(f"  0x950400: {cstr_at(0x950400, 300)}")
print(f"  0x9504b4: {cstr_at(0x9504b4, 500)}")
