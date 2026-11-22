"""Pack an IPA with the exact entry order i4Tools accepts.

Known-good layout (verified 2026-11-22):
    Payload/                              dir, method=0
    Payload/<Name>.app/                   dir, method=0
    Payload/<Name>.app/Info.plist         deflate   <-- Info.plist MUST come before the binary
    Payload/<Name>.app/<Name>             deflate

7-Zip sorts entries alphabetically, which puts the binary before Info.plist and
makes i4Tools report "file corrupted". This script controls the order explicitly.

Usage: python pack_ipa.py <out.ipa> <app_dir> <executable_name>
"""
import os
import sys
import time
import zipfile

out = sys.argv[1]
app_dir = sys.argv[2]          # ...\Payload\Name.app
name = sys.argv[3]

plist = os.path.join(app_dir, 'Info.plist')
binary = os.path.join(app_dir, name)
for p in (plist, binary):
    if not os.path.isfile(p):
        raise SystemExit('missing file: ' + p)

# i4Tools parses Info.plist and reports "file corrupted" for anything it cannot read.
# PowerShell 5.1 Set-Content -Encoding utf8 silently prepends a UTF-8 BOM -> guard here.
with open(plist, 'rb') as fh:
    head = fh.read(3)
if head == b'\xef\xbb\xbf':
    raise SystemExit('Info.plist starts with UTF-8 BOM; i4Tools will reject this IPA. '
                     'Rewrite it via [System.IO.File]::WriteAllText with UTF8Encoding(false).')

payload_dir = os.path.dirname(app_dir)          # ...\Payload
root = os.path.dirname(payload_dir)             # parent of Payload

if os.path.exists(out):
    os.remove(out)

entries = [
    ('Payload/', None),
    ('Payload/%s.app/' % name, None),
    ('Payload/%s.app/Info.plist' % name, plist),
    ('Payload/%s.app/%s' % (name, name), binary),
]

with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED, allowZip64=False) as z:
    for arcname, src in entries:
        if src is None:
            zi = zipfile.ZipInfo(arcname, date_time=time.localtime()[:6])
            zi.compress_type = zipfile.ZIP_STORED
            zi.external_attr = 0x10           # directory, matches i4Tools-accepted IPA
            zi.create_system = 3              # unix
            z.writestr(zi, b'')
        else:
            st = os.stat(src)
            zi = zipfile.ZipInfo(arcname, date_time=time.localtime()[:6])
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0x20           # regular file, matches known-good
            zi.create_system = 3
            zi.file_size = st.st_size
            with open(src, 'rb') as fh:
                z.writestr(zi, fh.read())

# verify
with zipfile.ZipFile(out) as z:
    names = z.namelist()
    assert names == [e[0] for e in entries], names
    bad = z.testzip()
    if bad:
        raise SystemExit('corrupt entry: ' + bad)
print('packed %s (%d bytes, %d entries, order ok)' % (out, os.path.getsize(out), len(names)))
