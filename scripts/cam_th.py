import json, re, sys
p = r"C:\Temp\cams\cameracaptured-2026-11-22-082219.ips"
raw = open(p, "r", encoding="utf-8", errors="replace").read()
# .ips = 第一行 JSON 头 + 后面 JSON 主体
nl = raw.index("\n")
body = raw[nl+1:]
try:
    d = json.loads(body)
except Exception as e:
    print("json parse fail:", e); sys.exit()

print("=== 基本信息 ===")
for k in ("procName","pid","exception","termination","faultingThread","captureTime","name","os_version"):
    if k in d:
        v = d[k]
        s = json.dumps(v, ensure_ascii=False)
        print(f"  {k} = {s[:300]}")

th = d.get("threads", [])
ft = d.get("faultingThread")
print(f"\n=== 崩溃线程 index={ft} (共 {len(th)} 线程) ===")
if isinstance(ft, int) and 0 <= ft < len(th):
    t = th[ft]
    print(f"  id={t.get('id')} name={t.get('name','')} queue={t.get('queue','')}")
    imgs = d.get("usedImages", [])
    frames = t.get("frames", [])
    print(f"  帧数: {len(frames)}")
    for fr in frames[:40]:
        idx = fr.get("imageIndex", -1)
        img = imgs[idx].get("name","?") if 0 <= idx < len(imgs) else "?"
        sym = fr.get("symbol","")
        off = fr.get("imageOffset", 0)
        print(f"    {img:28s} +0x{off:<8x} {sym}")
