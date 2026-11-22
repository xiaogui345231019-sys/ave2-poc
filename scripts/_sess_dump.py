import zstandard, json, io, sys, os

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

mode = sys.argv[1]

if mode == "compaction":
    for o in iter_events():
        if o.get("type") in ("compaction/summary", "compaction/start", "compaction/end", "session/title"):
            print("#### ", o.get("type"), "seq", o.get("seq"))
            print(json.dumps(o.get("data"), ensure_ascii=False, indent=1)[:20000])
            print()

elif mode == "users":
    for o in iter_events():
        if o.get("type") != "user/message":
            continue
        d = o.get("data", {})
        src = (d.get("source") or {}).get("kind")
        if src != "user":
            continue
        txt = "\n".join(c.get("text", "") for c in d.get("content", []) if c.get("type") == "text")
        print(f"[seq {o.get('seq')}] {txt.strip()}")
        print("-----")

elif mode == "timeline":
    cur_turn = None
    for o in iter_events():
        t = o.get("type")
        d = o.get("data", {})
        if t == "turn/start":
            print(f"\n========== TURN {d.get('turn')} seq={o.get('seq')} ==========")
        elif t == "user/message":
            src = (d.get("source") or {}).get("kind")
            if src != "user":
                continue
            txt = "\n".join(c.get("text", "") for c in d.get("content", []) if c.get("type") == "text").strip()
            if txt.startswith("Current runtime context") or txt.startswith("<system-reminder>"):
                continue
            print(f"[USER] {txt[:2000]}")
        elif t == "assistant/message":
            m = d.get("message", {})
            for c in m.get("content", []):
                if c.get("type") == "text" and c.get("text", "").strip():
                    print(f"[ASSIST {d.get('turn')}.{d.get('step')}] {c['text'].strip()[:900]}")
                elif c.get("type") == "tool-call":
                    name = c.get("name")
                    a = c.get("arguments") or ""
                    try:
                        aj = json.loads(a)
                    except Exception:
                        aj = {}
                    brief = aj.get("description") or aj.get("file_path") or aj.get("pattern") or aj.get("objective") or aj.get("command") or aj.get("tool") or ""
                    brief = str(brief).replace("\n", " ")[:220]
                    print(f"   <tool {name}> {brief}")

elif mode == "deliverables":
    for o in iter_events():
        if o.get("type") in ("deliverables/presented", "workspace/changes", "todo/write", "session/title"):
            print("####", o.get("type"), o.get("seq"))
            print(json.dumps(o.get("data"), ensure_ascii=False)[:4000])
            print()
