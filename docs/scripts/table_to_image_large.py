#!/usr/bin/env python3
"""Table infographics with 18px+ body text (≥12pt when displayed in Google Docs).

STYLE RULE: White canvas (#ffffff) only. No dark or black fills in table images.
Header row uses light blue fill with dark text.
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

import cairosvg

# Typography tuned for 300% zoom: large SVG fonts + 8x raster scale (~9600–19200px output).
FONT_TITLE = 36
FONT_HEADER = 32
FONT_KEY = 30
FONT_BODY = 28
FONT_BADGE = 28
LINE_H = 42
CELL_PAD_TOP = 44
SCALE = 8.0
CANVAS_W = 2400
# Google Docs / DOCX break very large embedded PNGs (~25M+ pixels or >8k edge).
MAX_RASTER_PIXELS = 24_000_000
MAX_RASTER_EDGE = 8192


def raster_scale_for_canvas(canvas_w: int, canvas_h: int, base: float = SCALE) -> float:
    if canvas_w <= 0 or canvas_h <= 0:
        return base
    by_pixels = (MAX_RASTER_PIXELS / (canvas_w * canvas_h)) ** 0.5
    by_edge = min(MAX_RASTER_EDGE / canvas_w, MAX_RASTER_EDGE / canvas_h)
    return max(1.0, min(base, by_pixels, by_edge))


def _typography(data_rows: int) -> dict:
    """Tighter layout for tall tables so raster output stays within embed limits."""
    compact = data_rows > 12
    return {
        "header": 28 if compact else FONT_HEADER,
        "key": 26 if compact else FONT_KEY,
        "body": 24 if compact else FONT_BODY,
        "badge": 24 if compact else FONT_BADGE,
        "line_h": 36 if compact else LINE_H,
        "cell_pad": 36 if compact else CELL_PAD_TOP,
        "row_min": 72 if compact else 90,
        "badge_h": 40 if compact else 46,
    }


def clean_markdown(text: str) -> str:
    """Strip lightweight markdown so infographics show plain text."""
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    return text.strip()


def title_font_size(title: str) -> int:
    if len(title) > 70:
        return 26
    if len(title) > 50:
        return 30
    return FONT_TITLE


def wrap_text(text: str, max_chars: int):
    if not text:
        return [""]
    words = text.split()
    if not words:
        return [""]
    lines = []
    curr = []
    curr_len = 0
    for w in words:
        while len(w) > max_chars:
            if curr:
                lines.append(" ".join(curr))
                curr = []
                curr_len = 0
            head, w = w[:max_chars], w[max_chars:]
            lines.append(head)
        if not w:
            continue
        if curr_len + len(w) + 1 > max_chars:
            lines.append(" ".join(curr))
            curr = [w]
            curr_len = len(w)
        else:
            curr.append(w)
            curr_len += len(w) + 1
    if curr:
        lines.append(" ".join(curr))
    return lines


def get_badge_color(text: str):
    t = text.lower().strip()
    if t in ("strong", "pass", "active", "yes", "allowed", "enabled", "ok", "healthy", "immediate"):
        return ("#dcfce7", "#15803d")
    if t in ("high", "recommended", "supported", "a2", "a1"):
        return ("#dbeafe", "#1d4ed8")
    if t in ("partial", "medium", "warn", "warning", "pending", "deprecated", "limited", "scheduled"):
        return ("#fef3c7", "#b45309")
    if t in ("none", "fail", "failed", "blocked", "critical", "no", "disabled", "denied", "a0"):
        return ("#fee2e2", "#b91c1c")
    return None


def markdown_table_to_svg(table_md: str, title: str = "") -> str:
    lines = [l.strip() for l in table_md.strip().splitlines() if l.strip()]
    rows = []
    for l in lines:
        if re.match(r"^[\|\s\-:]+$", l):
            continue
        cells = [clean_markdown(c.strip()) for c in l.strip("|").split("|")]
        rows.append(cells)
    if not rows:
        return ""

    num_cols = len(rows[0])
    for r in rows:
        while len(r) < num_cols:
            r.append("")

    data_rows = len(rows) - 1
    typo = _typography(data_rows)
    line_h = typo["line_h"]
    cell_pad = typo["cell_pad"]
    row_min = typo["row_min"]
    badge_h = typo["badge_h"]

    col_scale = 420 if num_cols >= 7 else 380
    canvas_w = max(CANVAS_W, min(5200, num_cols * col_scale))
    padding = 48
    content_w = canvas_w - (padding * 2)

    col_lengths = []
    for c in range(num_cols):
        lens = [len(rows[0][c])] + [len(r[c]) for r in rows[1:]]
        col_lengths.append(max(lens) if lens else 10)

    total_len = sum(col_lengths)
    col_widths = []
    for l in col_lengths:
        if num_cols >= 7:
            min_w = 140
        elif num_cols >= 5:
            min_w = 160
        elif num_cols >= 4:
            min_w = 180
        elif num_cols == 3:
            min_w = 280
        else:
            min_w = 420
        w = max(min_w, int((l / total_len) * content_w))
        col_widths.append(w)
    diff = content_w - sum(col_widths)
    col_widths[-1] += diff

    char_px = 13.5 if typo["body"] <= 24 else 14.5
    max_chars_per_col = [max(8, int(w / char_px) - 2) for w in col_widths]

    wrapped_header = [wrap_text(h, max_chars_per_col[c_idx]) for c_idx, h in enumerate(rows[0])]
    max_header_lines = max(len(h_lines) for h_lines in wrapped_header)
    header_h = max(72 if data_rows > 12 else 80, 32 + (max_header_lines * line_h))

    row_heights = []
    wrapped_rows = []
    for r in rows[1:]:
        row_lines = []
        max_lines_in_row = 1
        for c_idx in range(num_cols):
            cell_val = r[c_idx]
            cell_lines = wrap_text(cell_val, max_chars_per_col[c_idx])
            row_lines.append(cell_lines)
            max_lines_in_row = max(max_lines_in_row, len(cell_lines))
        wrapped_rows.append(row_lines)
        row_heights.append(max(row_min, 40 + (max_lines_in_row * line_h)))

    title_h = 72 if title else 0
    total_table_h = sum(row_heights) + header_h
    canvas_h = padding * 2 + title_h + total_table_h
    enum_dense = data_rows >= 10 and num_cols >= 5

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {canvas_w} {canvas_h}" width="{canvas_w}" height="{canvas_h}" overflow="visible" style="background-color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, Helvetica, Arial, sans-serif;">',
        "  <defs>",
        '    <filter id="table-shadow" x="-10%" y="-10%" width="120%" height="120%">',
        '      <feDropShadow dx="0" dy="5" stdDeviation="6" flood-opacity="0.09"/>',
        "    </filter>",
        "  </defs>",
    ]

    curr_y = padding
    if title:
        title_fs = title_font_size(title)
        svg.append(
            f'  <rect x="{padding}" y="{curr_y}" width="{content_w}" height="52" rx="8" fill="#f1f5f9" stroke="#cbd5e1" stroke-width="1"/>'
        )
        svg.append(
            f'  <text x="{padding + 22}" y="{curr_y + 36}" font-size="{title_fs}" font-weight="bold" fill="#0f172a">{html.escape(title)}</text>'
        )
        curr_y += title_h

    svg.append(f'  <g transform="translate({padding}, {curr_y})" filter="url(#table-shadow)">')
    svg.append(f'    <rect width="{content_w}" height="{total_table_h}" rx="8" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5"/>')
    svg.append(f'    <rect width="{content_w}" height="{header_h}" rx="8" fill="#dbeafe" stroke="#93c5fd" stroke-width="1"/>')
    svg.append(f'    <line x1="0" y1="{header_h}" x2="{content_w}" y2="{header_h}" stroke="#93c5fd" stroke-width="1.5"/>')

    curr_x = 0
    for c_idx, h_lines in enumerate(wrapped_header):
        for l_idx, hl in enumerate(h_lines):
            svg.append(
                f'    <text x="{curr_x + 18}" y="{40 + l_idx * line_h}" font-size="{typo["header"]}" font-weight="bold" fill="#0f172a">{html.escape(hl)}</text>'
            )
        curr_x += col_widths[c_idx]

    y_pos = header_h
    for r_idx, r_lines in enumerate(wrapped_rows):
        h = row_heights[r_idx]
        bg = "#f8fafc" if r_idx % 2 == 1 else "#ffffff"
        svg.append(f'    <rect y="{y_pos}" width="{content_w}" height="{h}" fill="{bg}"/>')
        svg.append(f'    <line x1="0" y1="{y_pos + h}" x2="{content_w}" y2="{y_pos + h}" stroke="#e2e8f0" stroke-width="1"/>')

        curr_x = 0
        for c_idx, cell_lines in enumerate(r_lines):
            col_w = col_widths[c_idx]
            display_cell = clean_markdown(rows[r_idx + 1][c_idx])
            badge = get_badge_color(display_cell)
            if badge and len(cell_lines) == 1 and len(display_cell) < 25:
                bg_col, txt_col = badge
                if enum_dense:
                    inset = 5
                    svg.append(
                        f'    <rect x="{curr_x + inset}" y="{y_pos + inset}" width="{col_w - inset * 2}" height="{h - inset * 2}" rx="6" fill="{bg_col}"/>'
                    )
                    svg.append(
                        f'    <text x="{curr_x + col_w / 2}" y="{y_pos + h / 2 + typo["badge"] / 3}" text-anchor="middle" font-size="{typo["badge"]}" font-weight="bold" fill="{txt_col}">{html.escape(display_cell)}</text>'
                    )
                else:
                    badge_w = min(len(display_cell) * 14 + 36, col_w - 16)
                    badge_x = curr_x + (col_w - badge_w) / 2
                    text_x = curr_x + col_w / 2
                    svg.append(
                        f'    <rect x="{badge_x}" y="{y_pos + 18}" width="{badge_w}" height="{badge_h}" rx="8" fill="{bg_col}"/>'
                    )
                    svg.append(
                        f'    <text x="{text_x}" y="{y_pos + 18 + badge_h - 10}" text-anchor="middle" font-size="{typo["badge"]}" font-weight="bold" fill="{txt_col}">{html.escape(display_cell)}</text>'
                    )
            else:
                font_weight = "bold" if c_idx == 0 else "normal"
                font_fill = "#0f172a" if c_idx == 0 else "#334155"
                font_size = typo["key"] if c_idx == 0 else typo["body"]
                text_x = curr_x + 18
                if c_idx == num_cols - 1 and len(cell_lines) == 1 and len(cell_lines[0]) > 18:
                    text_x = curr_x + 14
                for l_idx, line in enumerate(cell_lines):
                    svg.append(
                        f'    <text x="{text_x}" y="{y_pos + cell_pad + l_idx * line_h}" font-size="{font_size}" font-weight="{font_weight}" fill="{font_fill}">{html.escape(line)}</text>'
                    )
            curr_x += col_w
        y_pos += h

    svg.append("  </g>")
    svg.append("</svg>")
    return "\n".join(svg)


def extract_table_block(text: str) -> str:
    lines = text.splitlines()
    block = []
    started = False
    for l in lines:
        if l.strip().startswith("|"):
            started = True
            block.append(l)
        elif started:
            break
    return "\n".join(block)


def render_table_to_png(table_md: str, out_png_path: Path, title: str = "", scale: float = SCALE):
    table_md = extract_table_block(table_md)
    svg_str = markdown_table_to_svg(table_md, title=title)
    if not svg_str:
        print(f"[!] No table rows found for {out_png_path.name}; skipped.")
        return
    vb = re.search(r'viewBox="0 0 (\d+) (\d+)"', svg_str)
    if vb:
        cw, ch = int(vb.group(1)), int(vb.group(2))
        scale = raster_scale_for_canvas(cw, ch, scale)
    cairosvg.svg2png(bytestring=svg_str.encode("utf-8"), write_to=str(out_png_path), scale=scale)
    kb = out_png_path.stat().st_size // 1024
    scale_note = f", scale={scale:.2f}" if scale < SCALE else ""
    print(f"[+] Rendered large-font table: {out_png_path.name} ({kb} KB{scale_note})")
