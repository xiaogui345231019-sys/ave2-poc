import zstandard, json, io, sys, os

P = r"C:\Users\Administrator\.dsh\sessions\--C-Users-Administrator-Documents-deepseek-harness-default-workspace--\session-ac095e99-1b80-4971-90fd-ab256a5e5c61\session.v4.jsonl.zstd"
OUTDIR = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\_sess_ac095e99"
os.makedirs(OUTDIR, exist_ok=True)

def iter_events():
    dctx = zstandard.ZstdDecompressor()
    with open(P, "rb") as f:
        r = dctx.stream_reader(f)
        for raw in io.TextIOWrapper(r, encoding="utf-8", errors="replace"):
            raw = raw.strip()
            if not raw:
                continue
            try:
                yield json.loads(raw)
            except Exception:
                continue

i = 0
last = None
for o in iter_events():
    if o.get("type") == "compaction/summary":
        i += 1
        d = o.get("data", {})
        txt = "\n".join(b.get("text", "") for b in d.get("summary", []) if b.get("type") == "text")
        shadow = d.get("shadowedRange")
        fn = os.path.join(OUTDIR, f"summary_{i}.md")
        with open(fn, "w", encoding="utf-8") as f:
            f.write(f"<!-- seq={o.get('seq')} shadowed={shadow} -->\n")
            f.write(txt)
        print(f"wrote {fn} chars={len(txt)} seq={o.get('seq')} shadowed={shadow}")
        last = fn
print("LAST:", last)
