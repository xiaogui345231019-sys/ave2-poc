import struct
P = r"C:\Users\Administrator\AppData\Local\Sideloadly\sideloadly.exe"
data = open(P, "rb").read()
# PE arch
pe = struct.unpack_from("<I", data, 0x3c)[0]
machine = struct.unpack_from("<H", data, pe+4)[0]
print(f"PE machine = 0x{machine:04x}  (0x8664=x64, 0x14c=x86)")
# longer context around the redist string
i = data.find(b"Could not check redist at")
print(f"\n=== context @0x{i:x} ===")
frag = data[max(0,i-200):i+400]
txt = "".join(chr(c) if 32 <= c < 127 else "." for c in frag)
print(txt)
