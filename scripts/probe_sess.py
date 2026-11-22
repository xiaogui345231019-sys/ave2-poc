import zstandard, json, io, sys
p = r"C:\Users\Administrator\.dsh\sessions\--C-Users-Administrator-Documents-deepseek-harness-default-workspace--\3222c888-17bd-4649-b6b8-fbec4e72f08e\session.v4.jsonl.zstd"
dctx = zstandard.ZstdDecompressor()
with open(p,'rb') as f:
    data = dctx.stream_reader(f).read()
print("bytes:", len(data))
lines = data.decode('utf-8', 'replace').splitlines()
print("lines:", len(lines))
for i, ln in enumerate(lines[:3]):
    try:
        o = json.loads(ln)
    except Exception as e:
        print(i, "parse err", e); continue
    print("--- line", i, "keys:", list(o.keys())[:20])
    print(json.dumps(o, ensure_ascii=False)[:1200])
