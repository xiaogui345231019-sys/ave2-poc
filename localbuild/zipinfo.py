"""Inspect a zip's per-entry metadata (to clone a known-good IPA layout)."""
import sys
import zipfile

for p in sys.argv[1:]:
    print("=" * 70)
    print(p)
    with zipfile.ZipFile(p) as z:
        for i in z.infolist():
            print("  %-46s method=%d flag=%#06x extattr=%#010x csize=%-7d size=%-7d date=%s"
                  % (i.filename, i.compress_type, i.flag_bits, i.external_attr,
                     i.compress_size, i.file_size, i.date_time))
        print("  comment:", z.comment)
