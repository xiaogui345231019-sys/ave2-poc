import re, os
p = r"E:\IOS18.7.2\work\kext\ave2_a14_18.7.2"
print("kext exists:", os.path.exists(p), os.path.getsize(p) if os.path.exists(p) else 0)
data = open(p, "rb").read()
hits = []
for m in re.finditer(rb"[ -~]{5,}", data):
    s = m.group()
    if b"UserClient" in s or b"userClient" in s or b"Client" in s:
        hits.append((m.start(), s))
print(f"=== Client-related strings: {len(hits)} ===")
for off, s in hits[:40]:
    print(f"  0x{off:08x}  {s.decode('ascii', 'replace')}")
