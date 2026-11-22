import zstandard, json, io

P = r"C:\Users\Administrator\.dsh\sessions\--C-Users-Administrator-Documents-deepseek-harness-default-workspace--\session-ac095e99-1b80-4971-90fd-ab256a5e5c61\session.v4.jsonl.zstd"

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

last = None
for o in iter_events():
    if o.get("type") == "assistant/message":
        d = o.get("data") or {}
        for c in (d.get("message") or {}).get("content", []):
            if c.get("type") == "text" and c.get("text", "").strip():
                last = (o.get("seq"), c["text"])

print("SEQ:", last[0])
print(last[1])
