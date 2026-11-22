import csv, io, sys
path = r"C:\Temp\sl.csv"
with open(path, "rb") as f:
    head = f.read(4)
print("head bytes:", head)
enc = "utf-16-le" if head[:2] == b"\xff\xfe" else ("utf-8-sig" if head[:3] == b"\xef\xbb\xbf" else "utf-8")
print("encoding:", enc)

rows = []
with open(path, "r", encoding=enc, errors="replace", newline="") as f:
    r = csv.reader(f)
    header = next(r, None)
    print("header:", header)
    for row in r:
        if len(row) < 6: continue
        proc = row[1]; op = row[3]; p = row[4]; res = row[5]
        if "sideloadly" not in proc.lower(): continue
        bad = ("NOT FOUND" in res) or ("NOT A DIRECTORY" in res) or ("INVALID" in res) or ("DENIED" in res) or ("NAME INVALID" in res)
        if not bad: continue
        rows.append((op, p, res, row[6] if len(row) > 6 else ""))

print(f"\n=== failing ops by sideloadly: {len(rows)} ===")
# unique paths
seen = {}
for op, p, res, det in rows:
    key = (op, p, res)
    seen[key] = seen.get(key, 0) + 1
items = sorted(seen.items(), key=lambda kv: -kv[1])
for (op, p, res), n in items[:60]:
    print(f"  [{n}x] {op:22s} {res:20s} {p[:150]}")
