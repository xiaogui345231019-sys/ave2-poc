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

START = int(sys.argv[1]) if len(sys.argv) > 1 else 0
TEXT_CAP = int(sys.argv[2]) if len(sys.argv) > 2 else 1200

for o in iter_events():
    seq = o.get("seq") or 0
    if seq < START:
        continue
    t = o.get("type")
    d = o.get("data") or {}
    if t == "turn/start":
        print(f"\n===== TURN {d.get('turn')} (seq {seq}) =====")
    elif t == "user/message":
        src = (d.get("source") or {}).get("kind")
        txt = "\n".join(c.get("text", "") for c in d.get("content", []) if c.get("type") == "text").strip()
        if src == "user":
            print(f"[USER seq={seq}] {txt[:TEXT_CAP]}")
        elif src in ("agent", "subagent"):
            print(f"[INBOX from {src} seq={seq}] {txt[:400]}")
    elif t == "assistant/message":
        m = d.get("message") or {}
        for c in m.get("content", []):
            if c.get("type") == "text" and c.get("text", "").strip():
                print(f"[ASSIST t{d.get('turn')}.s{d.get('step')}] {c['text'].strip()[:TEXT_CAP]}")
            elif c.get("type") == "tool-call":
                a = c.get("arguments") or ""
                try:
                    aj = json.loads(a)
                except Exception:
                    aj = {}
                brief = aj.get("description") or aj.get("file_path") or aj.get("objective") or aj.get("pattern") or str(aj)[:200]
                print(f"    <tool {c.get('name')}> {str(brief).replace(chr(10),' ')[:200]}")
    elif t in ("deliverables/presented",):
        print(f"[PRESENTED seq={seq}] {json.dumps(d, ensure_ascii=False)[:1500]}")
