# -*- coding: utf-8 -*-
"""审计 tex_export 的 1434 张：分类 UI / 立绘 / 空白 / 噪声 / 可疑真贴图"""
import os, sys, collections
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import numpy as np
from PIL import Image, ImageDraw

EXP = r"D:\ReverseKit\projects\apk_yyslscn\tex_export"
OUT = r"D:\ReverseKit\projects\apk_yyslscn\RENDER_CHECK"


def stats(p):
    with Image.open(p) as im:
        im = im.convert("RGB")
        w, h = im.size
        a = np.asarray(im, dtype=np.int16)
    std = float(a.std())
    mean = float(a.mean())
    # 邻域差（水平方向）
    d = np.abs(np.diff(a, axis=1)).mean() if w > 1 else 0.0
    # 高亮比例（接近纯白）
    white = float((a.min(axis=2) > 240).mean())
    return w, h, std, mean, d, white


cats = collections.Counter()
buckets = collections.defaultdict(list)
for f in sorted(os.listdir(EXP)):
    if not f.lower().endswith(".png"):
        continue
    p = os.path.join(EXP, f)
    try:
        w, h, std, mean, d, white = stats(p)
    except Exception:
        cats["损坏"] += 1
        continue
    if white > 0.97:
        c = "纯白/遮罩"
    elif d > 55:
        c = "噪声(解码失败)"
    elif max(w, h) <= 64:
        c = "小图标 UI"
    elif h >= 1.8 * w:
        c = "立绘/条状 UI"
    elif std < 6:
        c = "低对比(疑似失败)"
    else:
        c = "可疑真贴图"
    cats[c] += 1
    buckets[c].append((f, w, h, std, mean, d))

total = sum(cats.values())
print("total", total)
for k, v in cats.most_common():
    print(f"  {k:18} {v}")

# 给"可疑真贴图"出联络表
sel = sorted(buckets["可疑真贴图"], key=lambda t: -t[1] * t[2])[:48]
CELL = 200
COLS = 8
rows = max(1, (len(sel) + COLS - 1) // COLS)
sheet = Image.new("RGB", (COLS * CELL, rows * (CELL + 16)), (25, 25, 25))
d = ImageDraw.Draw(sheet)
for i, (f, w, h, std, mean, dd) in enumerate(sel):
    r, c = divmod(i, COLS)
    try:
        with Image.open(os.path.join(EXP, f)) as im:
            im = im.convert("RGB")
            im.thumbnail((CELL - 4, CELL - 4))
            sheet.paste(im, (c * CELL + 2, r * (CELL + 16) + 2))
    except Exception:
        pass
    d.text((c * CELL + 4, r * (CELL + 16) + CELL - 4), f"{f[:14]} {w}x{h}", fill=(215, 215, 215))
sp = os.path.join(OUT, "suspect_real_sheet.png")
sheet.save(sp)
print("sheet", sp, sheet.size, "n", len(sel))
