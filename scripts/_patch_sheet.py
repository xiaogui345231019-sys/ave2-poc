# -*- coding: utf-8 -*-
"""patch_tex 联络表：只放 >=256x256 的，看是不是真材质贴图"""
import os, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from PIL import Image, ImageDraw

D = sys.argv[1] if len(sys.argv) > 1 else r"D:\ReverseKit\projects\apk_yyslscn\patch_tex"
OUT = sys.argv[2] if len(sys.argv) > 2 else r"D:\ReverseKit\projects\apk_yyslscn\RENDER_CHECK\patch_sheet.png"
MIN = int(sys.argv[3]) if len(sys.argv) > 3 else 256
COLS = int(sys.argv[4]) if len(sys.argv) > 4 else 8

files = []
for f in sorted(os.listdir(D)):
    if not f.lower().endswith(".png"):
        continue
    try:
        with Image.open(os.path.join(D, f)) as im:
            w, h = im.size
    except Exception:
        continue
    if w >= MIN and h >= MIN:
        files.append((f, w, h))

print("picked", len(files))
CELL = 200
rows = (len(files) + COLS - 1) // COLS
sheet = Image.new("RGB", (COLS * CELL, max(1, rows) * (CELL + 16)), (25, 25, 25))
d = ImageDraw.Draw(sheet)
for i, (f, w, h) in enumerate(files):
    r, c = divmod(i, COLS)
    try:
        with Image.open(os.path.join(D, f)) as im:
            im = im.convert("RGB")
            im.thumbnail((CELL - 4, CELL - 4))
            sheet.paste(im, (c * CELL + 2, r * (CELL + 16) + 2))
    except Exception:
        pass
    d.text((c * CELL + 4, r * (CELL + 16) + CELL - 6), f[:26], fill=(210, 210, 210))
sheet.save(OUT)
print("sheet", OUT, sheet.size)
