import csv
path = r"C:\Temp\sl.csv"
ipa_rows = []
dir_ops = []
with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
    r = csv.reader(f)
    next(r, None)
    for row in r:
        if len(row) < 6: continue
        proc = row[1].lower()
        if "sideloadly" not in proc: continue
        op, p, res = row[3], row[4], row[5]
        if ".ipa" in p.lower():
            ipa_rows.append((op, p, res, row[6] if len(row) > 6 else ""))
        if op in ("QueryDirectory","QueryOpen","DirectoryControl"):
            dir_ops.append((op, p, res))

print(f"=== ops on .ipa paths: {len(ipa_rows)} ===")
seen = {}
for op,p,res,det in ipa_rows:
    seen[(op,p,res)] = seen.get((op,p,res),0)+1
for (op,p,res),n in sorted(seen.items(), key=lambda kv:-kv[1])[:30]:
    print(f"  [{n}x] {op:20s} {res:24s} {p[:130]}")

print(f"\n=== QueryDirectory ops: {len(dir_ops)} ===")
seen2 = {}
for op,p,res in dir_ops:
    seen2[(op,p,res)] = seen2.get((op,p,res),0)+1
for (op,p,res),n in sorted(seen2.items(), key=lambda kv:-kv[1])[:25]:
    print(f"  [{n}x] {op:14s} {res:24s} {p[:130]}")
