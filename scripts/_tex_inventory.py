# -*- coding: utf-8 -*-
"""盘点 tex_export / XX3 贴图到底是什么：尺寸分布 + 联络表"""
import os, struct, sys, collections
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import numpy as np
from PIL import Image, ImageDraw

ROOT = r"D:\ReverseKit\projects\apk_yyslscn"
EXP = os.path.join(ROOT, "tex_export")
OUT = os.path.join(ROOT, "RENDER_CHECK")

files = sorted(os.listdir(EXP))
sizes = []
dims = collections.Counter()
small = 0
for f in files:
    if not f.lower().endswith(".png"):
        continue
    p = os.path.join(EXP, f)
    sizes.append(os.path.getsize(p))
    try:
        with Image.open(p) as im:
            w, h = im.size
        dims[(w, h)] += 1
        if w * h <= 64 * 64:
            small += 1
    except Exception:
        pass

print("count", len(sizes), "total MB", round(sum(sizes) / 1048576, 1))
print("<=64x64:", small)
print("top dims:")
for (w, h), c in dims.most_common(25):
    print(f"  {w}x{h}\t{c}")

# 联络表：取 60 张随机/分布样本
sel = [f for f in files if f.lower().endswith(".png")]
step = max(1, len(sel) // 60)
pick = sel[::step][:60]
CELL = 160
COLS = 10
ROWS = (len(pick) + COLS - 1) // COLS
sheet = Image.new("RGB", (COLS * CELL, ROWS * (CELL + 14)), (30, 30, 30))
d = ImageDraw.Draw(sheet)
for i, f in enumerate(pick):
    r, c = divmod(i, COLS)
    try:
        with Image.open(os.path.join(EXP, f)) as im:
            im = im.convert("RGB")
            im.thumbnail((CELL - 4, CELL - 4))
            sheet.paste(im, (c * CELL + 2, r * (CELL + 14) + 2))
        d.text((c * CELL + 4, r * (CELL + 14) + CELL - 8), f[:18], fill=(200, 200, 200))
    except Exception:
        pass
p = os.path.join(OUT, "tex_export_sheet.png")
sheet.save(p)
print("sheet:", p, sheet.size)
