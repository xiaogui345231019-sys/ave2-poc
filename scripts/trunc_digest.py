import zstandard, json, os
BASE=r"C:\Users\Administrator\.dsh\sessions\--C-Users-Administrator-Documents-deepseek-harness-default-workspace--"
WANT={"2828856b":"idx110#1","ba5fff94":"idx110#3","61e29a11":"IOMFB sel",
      "e91cc495":"vm_map d8","6738e98a":"64747 PoC spec","133e6c76":"64747 PoC #1"}
def text_of(c):
    if isinstance(c,str): return c
    if isinstance(c,list): return "\n".join(x.get("text","") for x in c if isinstance(x,dict) and x.get("type")=="text")
    return ""
for name in os.listdir(BASE):
    key=name[:8]
    if key not in WANT: continue
    p=os.path.join(BASE,name,"session.v4.jsonl.zstd")
    if not os.path.isfile(p): continue
    dctx=zstandard.ZstdDecompressor()
    with open(p,"rb") as f: raw=dctx.stream_reader(f).read()
    label=""; last=""; tools=0; ss=se=0; lastacts=[]
    for ln in raw.decode("utf-8","replace").splitlines():
        try: o=json.loads(ln)
        except: continue
        t=o.get("type","")
        if t=="subagent/descriptor": label=(o.get("data") or {}).get("label","")
        elif t=="step/start": ss+=1
        elif t=="step/end": se+=1
        elif t=="tool/call":
            tools+=1
            nm=(o.get("data") or {}).get("name") or (o.get("data") or {}).get("tool")
            if nm: lastacts.append(nm)
        elif t=="assistant/message":
            m=(o.get("data") or {}).get("message") or {}
            tx=text_of(m.get("content")).strip()
            if tx: last=tx
    print(f"===== [{key}] {label}  tools={tools} steps={se}/{ss} =====")
    print("最近工具:", ", ".join(lastacts[-6:]))
    print("断点文本:", (last[:700] if last else "(无)"))
    print()
