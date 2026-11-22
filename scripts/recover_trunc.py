#!/usr/bin/env python3
"""Recover reasoning + tool trail from truncated subagent sessions.

usage: python recover_trunc.py <idprefix>[,<idprefix>...] <outfile.md>
"""
import json
import os
import sys

import zstandard

BASE = r'C:\Users\Administrator\.dsh\sessions\--C-Users-Administrator-Documents-deepseek-harness-default-workspace--'


def text_of(c):
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        out = []
        for x in c:
            if isinstance(x, dict) and x.get('type') == 'text':
                out.append(x.get('text', ''))
            elif isinstance(x, dict) and x.get('type') in ('thinking', 'reasoning'):
                out.append('[THINKING] ' + x.get('thinking', x.get('text', '')))
        return '\n'.join(out)
    return ''


def fmt_call(d):
    name = d.get('name') or d.get('tool') or '?'
    args = d.get('input') or d.get('arguments') or {}
    try:
        s = json.dumps(args, ensure_ascii=False)
    except Exception:
        s = str(args)
    if len(s) > 700:
        s = s[:700] + ' …'
    return f'`{name}` {s}'


def main():
    prefixes = [x.strip() for x in sys.argv[1].split(',') if x.strip()]
    out = sys.argv[2]
    blocks = []
    for pref in prefixes:
        hits = [n for n in os.listdir(BASE) if n.startswith(pref)]
        if not hits:
            blocks.append(f'## {pref}\n\n(未找到会话)\n')
            continue
        name = hits[0]
        p = os.path.join(BASE, name, 'session.v4.jsonl.zstd')
        dctx = zstandard.ZstdDecompressor()
        with open(p, 'rb') as f:
            raw = dctx.stream_reader(f).read()
        label = ''
        lines = [f'## 会话 `{name}`\n']
        step = 0
        for ln in raw.decode('utf-8', 'replace').splitlines():
            try:
                o = json.loads(ln)
            except Exception:
                continue
            t = o.get('type', '')
            d = o.get('data') or {}
            if t == 'subagent/descriptor':
                label = d.get('label', '')
                lines[0] = f'## 会话 `{name}` —— {label}\n'
            elif t == 'step/start':
                step += 1
                lines.append(f'\n### step {step}\n')
            elif t == 'assistant/message':
                m = d.get('message') or {}
                tx = text_of(m.get('content')).strip()
                if tx:
                    lines.append(tx + '\n')
            elif t == 'tool/call':
                lines.append(f'> TOOL {fmt_call(d)}\n')
            elif t == 'tool/result':
                r = d.get('result') or d.get('content') or ''
                s = r if isinstance(r, str) else json.dumps(r, ensure_ascii=False)
                if len(s) > 500:
                    s = s[:500] + ' …'
                lines.append(f'> RESULT {s}\n')
        blocks.append('\n'.join(lines))
    with open(out, 'w', encoding='utf-8') as f:
        f.write('# 掐断子代理的推理与工具轨迹（恢复）\n\n')
        f.write('\n\n---\n\n'.join(blocks))
    print(f'wrote {out}  ({os.path.getsize(out)//1024} KB)')


if __name__ == '__main__':
    main()
