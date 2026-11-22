import zstandard, json, collections, io, sys, os

P = r"C:\Users\Administrator\.dsh\sessions\--C-Users-Administrator-Documents-deepseek-harness-default-workspace--\session-ac095e99-1b80-4971-90fd-ab256a5e5c61\session.v4.jsonl.zstd"
OUT = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\_sess_ac095e99"

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

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "types"
    if mode == "types":
        c = collections.Counter()
        for o in iter_events():
            c[o.get("type")] += 1
        for k, v in c.most_common():
            print(v, k)
    elif mode == "sample":
        want = sys.argv[2]
        n = 0
        for o in iter_events():
            if o.get("type") == want:
                print(json.dumps(o, ensure_ascii=False)[:2000])
                print("====")
                n += 1
                if n >= 4:
                    break

if __name__ == "__main__":
    main()
