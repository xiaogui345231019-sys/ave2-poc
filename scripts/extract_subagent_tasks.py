#!/usr/bin/env python3
"""Extract subagent tasks (prompts + completion state) from DSH session files.

usage: python extract_subagent_tasks.py [--parent session-xxxx] [--out PATH]
"""
import collections
import json
import os
import sys

import zstandard

BASE = r'C:\Users\Administrator\.dsh\sessions\--C-Users-Administrator-Documents-deepseek-harness-default-workspace--'
PARENT = 'session-5cdf58a2-c117-4ac6-b4a4-c55bc9dba937'
OUT = r'E:\IOS18.7.2\out\subagent-tasks.md'


def read_session(path):
    dctx = zstandard.ZstdDecompressor()
    with open(path, 'rb') as f:
        raw = dctx.stream_reader(f).read()
    return raw.decode('utf-8', 'replace').splitlines()


def parse(lines):
    meta = None
    recs = []
    for ln in lines:
        try:
            o = json.loads(ln)
        except Exception:
            continue
        if meta is None and o.get('type') == 'session':
            meta = o
            continue
        recs.append(o)
    return meta, recs


def text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for c in content:
            if isinstance(c, dict) and c.get('type') == 'text':
                out.append(c.get('text', ''))
            elif isinstance(c, str):
                out.append(c)
        return '\n'.join(out)
    return ''


def main():
    parent = PARENT
    if '--parent' in sys.argv:
        parent = sys.argv[sys.argv.index('--parent') + 1]
    out_path = OUT
    if '--out' in sys.argv:
        out_path = sys.argv[sys.argv.index('--out') + 1]

    items = []
    for name in os.listdir(BASE):
        p = os.path.join(BASE, name, 'session.v4.jsonl.zstd')
        if not os.path.isfile(p):
            continue
        try:
            lines = read_session(p)
        except Exception as e:  # noqa: BLE001
            print(f'!! {name}: {e}')
            continue
        meta, recs = parse(lines)
        if not meta or meta.get('parentSession') != parent:
            continue
        label = ''
        prompt = ''
        steps_start = steps_end = tools = 0
        last_assistant = ''
        last_type = ''
        created = meta.get('createdAt', 0)
        users = []
        for o in recs:
            t = o.get('type', '')
            last_type = t or last_type
            if t == 'subagent/descriptor':
                label = (o.get('data') or {}).get('label', '')
            elif t == 'step/start':
                steps_start += 1
            elif t == 'step/end':
                steps_end += 1
            elif t == 'tool/call':
                tools += 1
            elif t == 'user/message':
                m = (o.get('data') or {}).get('message') or {}
                users.append(text_of(m.get('content')))
            elif t == 'assistant/message':
                m = (o.get('data') or {}).get('message') or {}
                txt = text_of(m.get('content'))
                if txt.strip():
                    last_assistant = txt
        if users:
            prompt = max(users, key=len)
        truncated = steps_start > steps_end
        items.append({
            'id': name,
            'label': label,
            'created': created,
            'steps_start': steps_start,
            'steps_end': steps_end,
            'tools': tools,
            'truncated': truncated,
            'prompt': prompt,
            'last': last_assistant,
            'last_type': last_type,
            'bytes': os.path.getsize(p),
        })

    items.sort(key=lambda x: (x['created'], x['id']))

    # group by label to spot re-dispatch pairs
    bylabel = collections.defaultdict(list)
    for it in items:
        bylabel[it['label']].append(it)

    lines = []
    w = lines.append
    w(f'# 子代理任务清单（parent = `{parent}`）\n')
    w(f'> 提取自 `{BASE}` · 共 **{len(items)}** 个会话 · 去重后 **{len(bylabel)}** 个任务标签\n')
    w('> 判据（项目自定义）：**最后一条是 `step/start` 而没有对应 `step/end`** → 被掐断。\n')

    w('## 0. 总表\n')
    w('| # | label | session id | 大小 | 工具调用 | step/end | 状态 |')
    w('|---|---|---|---|---|---|---|')
    for i, it in enumerate(items, 1):
        st = '**掐断**' if it['truncated'] else '走完'
        w(f"| {i} | {it['label']} | `{it['id'][:8]}` | {it['bytes']//1024} KB | {it['tools']} | "
          f"{it['steps_end']}/{it['steps_start']} | {st} |")

    w('\n## 1. 重派关系（同标签多会话）\n')
    for lb, lst in bylabel.items():
        if len(lst) > 1:
            ids = ' → '.join(f"`{x['id'][:8]}`({'掐断' if x['truncated'] else '走完'})" for x in lst)
            w(f"- **{lb}**：{ids}")

    w('\n## 2. 逐个任务：任务书 + 收尾状态\n')
    for lb, lst in bylabel.items():
        it = lst[-1]  # latest attempt
        w(f"### {lb}\n")
        w(f"- 会话：`{it['id']}` · 工具调用 {it['tools']} 次 · step/end {it['steps_end']}/{it['steps_start']}"
          f" · {'**掐断（未走完）**' if it['truncated'] else '走完'} · 最后事件 `{it['last_type']}`")
        if len(lst) > 1:
            w(f"- 该任务共派 {len(lst)} 次：" + '、'.join(f"`{x['id'][:8]}`" for x in lst))
        p = it['prompt'].strip()
        if len(p) > 6000:
            p = p[:3000] + '\n…（中略）…\n' + p[-3000:]
        w('\n<details><summary>任务书全文（点击展开）</summary>\n')
        w('```')
        w(p)
        w('```')
        w('</details>\n')
        if it['last'].strip():
            last = it['last'].strip()
            if len(last) > 1800:
                last = last[:1800] + ' …'
            w('**最后一条 assistant 输出（断点处）**\n')
            w('```')
            w(last)
            w('```\n')
        w('---\n')

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f'wrote {out_path}  items={len(items)} labels={len(bylabel)}')
    for it in items:
        print(f"  {it['id'][:8]}  {'TRUNC' if it['truncated'] else 'done '}  tools={it['tools']:3d}  {it['label']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
