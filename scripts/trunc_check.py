import zstandard, json, os
BASE=r"C:\Users\Administrator\.dsh\sessions\--C-Users-Administrator-Documents-deepseek-harness-default-workspace--"
for name in os.listdir(BASE):
    p=os.path.join(BASE,name,"session.v4.jsonl.zstd")
    if not os.path.isfile(p): continue
    try:
        dctx=zstandard.ZstdDecompressor()
        with open(p,"rb") as f: raw=dctx.stream_reader(f).read()
    except Exception: continue
    meta=None; recs=[]
    for ln in raw.decode("utf-8","replace").splitlines():
        try: o=json.loads(ln)
        except: continue
        if meta is None and o.get("type")=="session": meta=o; continue
        recs.append(o)
    if not meta or meta.get("parentSession")!="session-5cdf58a2-c117-4ac6-b4a4-c55bc9dba937": continue
    ss=sum(1 for r in recs if r.get("type")=="step/start")
    se=sum(1 for r in recs if r.get("type")=="step/end")
    if ss<=se: continue
    label=next(((r.get("data") or {}).get("label","") for r in recs if r.get("type")=="subagent/descriptor"),"")
    tail=[r.get("type") for r in recs[-3:]]
    print(f"{name[:8]}  steps={se}/{ss}  last={tail}  {label}")
