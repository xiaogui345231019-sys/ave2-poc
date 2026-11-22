import zstandard, json, collections
p = r"C:\Users\Administrator\.dsh\sessions\--C-Users-Administrator-Documents-deepseek-harness-default-workspace--\3222c888-17bd-4649-b6b8-fbec4e72f08e\session.v4.jsonl.zstd"
dctx = zstandard.ZstdDecompressor()
with open(p,'rb') as f: data = dctx.stream_reader(f).read()
lines = data.decode('utf-8','replace').splitlines()
cnt = collections.Counter()
first_user = None
for ln in lines[1:]:
    try: o=json.loads(ln)
    except: continue
    t=o.get('type'); cnt[t]+=1
    if first_user is None and t and ('message' in t or 'prompt' in t):
        s=json.dumps(o,ensure_ascii=False)
        if 'role' in s and 'user' in s:
            first_user=o
print("event types:", dict(cnt))
if first_user:
    print("--- first user-ish record ---")
    print(json.dumps(first_user, ensure_ascii=False)[:2500])
