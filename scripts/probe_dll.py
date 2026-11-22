import os, zipfile, io
P = r"C:\Users\Administrator\AppData\Local\Sideloadly\sideloadly.dll"
data = open(P, "rb").read(4096)
print("first 32 bytes:", data[:32])
print("hex:", data[:16].hex())
# common container signatures
sigs = {
    b"PK\x03\x04": "ZIP (local file header)",
    b"PK\x05\x06": "ZIP (empty)",
    b"\x1f\x8b": "GZIP",
    b"MZ": "PE executable",
    b"\x7fELF": "ELF",
    b"7z\xbc\xaf": "7-Zip",
    b"Rar!": "RAR",
    b"\xfd7zXZ": "XZ",
}
for s, name in sigs.items():
    if data.startswith(s):
        print("=> container:", name)
        break
else:
    print("=> unknown signature")
# try zipfile
try:
    z = zipfile.ZipFile(P)
    names = z.namelist()
    print(f"zip members: {len(names)}")
    for n in names[:25]: print("   ", n)
except Exception as e:
    print("not a zip:", e)
