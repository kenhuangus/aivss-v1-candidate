#!/usr/bin/env python3
"""Audit table SVG viewBox widths and column counts."""
from __future__ import annotations

import re
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from table_to_image_large import markdown_table_to_svg, title_font_size, CANVAS_W

md = Path(__file__).resolve().parent.parent / "AIVSS-1.0-Google-Doc.md"
lines = md.read_text(encoding="utf-8").splitlines()
tables: list[tuple[str, str]] = []
i = 0
while i < len(lines):
    m = re.match(r"^<!--table:(.*?)-->$", lines[i].strip())
    if m:
        title = m.group(1)
        block: list[str] = []
        i += 1
        while i < len(lines) and lines[i].startswith("|"):
            block.append(lines[i])
            i += 1
        tables.append((title, "\n".join(block)))
        continue
    i += 1

for n, (title, block) in enumerate(tables, 1):
    rows = [
        [c.strip() for c in l.strip("|").split("|")]
        for l in block.splitlines()
        if l.strip().startswith("|") and not re.match(r"^[\|\s\-:]+$", l.strip())
    ]
    cols = len(rows[0]) if rows else 0
    svg = markdown_table_to_svg(block, title=title)
    vb = re.search(r'viewBox="0 0 (\d+) (\d+)"', svg)
    w, h = (int(vb.group(1)), int(vb.group(2))) if vb else (0, 0)
    issues = []
    if cols >= 7 and w < cols * 420:
        issues.append("canvas may be narrow for 7+ cols")
    title_fs = title_font_size(title)
    title_est_w = len(title) * (title_fs * 0.55)
    if title and title_est_w > CANVAS_W - 120:
        issues.append("title may clip")
    flag = " !!" if issues else ""
    print(f"{n:2d}{flag} {cols}c {w}x{h}  {title[:60]}{'...' if len(title)>60 else ''}")
    if issues:
        print(f"     -> {', '.join(issues)}")
