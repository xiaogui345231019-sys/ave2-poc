import json, os, glob
for p in glob.glob(r"C:\Temp\cams2\*.ips"):
    raw = open(p,"r",encoding="utf-8",errors="replace").read()
    nl = raw.index("\n"); d = json.loads(raw[nl+1:])
    print(f"\n=== {os.path.basename(p)} ===")
    print("  exception  :", json.dumps(d.get("exception",""))[:180])
    print("  termination:", json.dumps(d.get("termination",""))[:180])
    ft = d.get("faultingThread")
    th = d.get("threads", []); imgs = d.get("usedImages", [])
    if isinstance(ft,int) and 0 <= ft < len(th):
        t = th[ft]
        print(f"  faulting thread {ft}: name={t.get('name','')} queue={t.get('queue','')}")
        for fr in t.get("frames", [])[:8]:
            i = fr.get("imageIndex",-1)
            nm = imgs[i].get("name","?") if 0<=i<len(imgs) else "?"
            print(f"     {nm:24s} +0x{fr.get('imageOffset',0):<8x} {fr.get('symbol','')}")
