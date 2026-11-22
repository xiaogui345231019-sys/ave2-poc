import re
p = r"E:\IOS18.7.2\work\kext\ave2_a14_18.7.2"
data = open(p, "rb").read()

def scan(patterns, label):
    print(f"=== {label} ===")
    seen = set()
    for m in re.finditer(rb"[ -~]{5,}", data):
        s = m.group().decode("ascii", "replace")
        for pat in patterns:
            if pat.lower() in s.lower():
                key = (m.start(), s)
                if key not in seen:
                    seen.add(key)
                    print(f"  0x{m.start():08x}  {s[:110]}")
                break
    print(f"  -> {len(seen)} hits")

scan(["UserClient"], "UserClient (exact, any case)")
scan(["com.apple.driver.AppleAVE2"], "bundle id / class names")
