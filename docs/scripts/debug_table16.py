#!/usr/bin/env python3
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from table_to_image_large import markdown_table_to_svg, markdown_table_to_svg as mts

md = Path(__file__).resolve().parent.parent / "AIVSS-1.0-Google-Doc.md"
block = re.search(
    r"<!--table:BOD 26-04 Table 1.*?-->\n((?:\|.*\n)+)", md.read_text(encoding="utf-8")
).group(1)
svg = markdown_table_to_svg(block, title="BOD 26-04 Table 1 (16 rows)")
vb = re.search(r'viewBox="0 0 (\d+) (\d+)"', svg)
print("canvas", vb.groups() if vb else None)
badges = re.findall(r'<rect x="(\d+)" y="(\d+)" width="(\d+)" height="46"', svg)
print("badge count", len(badges))
texts = re.findall(r'<text x="(\d+)" y="(\d+)"[^>]*>([^<]+)</text>', svg)
timeline = [t for t in texts if "day" in t[2] or "Fix" in t[2] or "forensic" in t[2]]
print("timeline samples:")
for t in timeline:
    x, y, txt = t
    print(f"  x={x} len={len(txt)} text={txt!r} est_right={int(x)+len(txt)*18}")
print("forensic:", [t for t in texts if "forensic" in t[2]])

from table_to_image_large import render_table_to_png, raster_scale_for_canvas

out = Path(__file__).resolve().parent.parent / "assets" / "tables" / "table_infographic_16.png"
render_table_to_png(block, out, title="BOD 26-04 Table 1 (16 rows)")
cw, ch = map(int, vb.groups())
sc = raster_scale_for_canvas(cw, ch)
print("raster scale", round(sc, 2), "output px", int(cw * sc), int(ch * sc), "total", int(cw * sc) * int(ch * sc))
print("file KB", out.stat().st_size // 1024)
