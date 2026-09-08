#!/usr/bin/env python3
"""Analyze Google Doc JSON for section boundaries and comment quotes."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

DOC_JSON = Path(r"C:\Users\kenhu\AppData\Local\Temp\aivss-v1-candidate\doc-work\doc-full.json")


def iter_paragraphs(doc: dict):
    for tab in doc.get("tabs") or []:
        tab_id = (tab.get("tabProperties") or {}).get("tabId", "t.0")
        body = (tab.get("documentTab") or {}).get("body") or {}
        for el in body.get("content") or []:
            para = el.get("paragraph")
            if not para:
                continue
            style = (para.get("paragraphStyle") or {}).get("namedStyleType", "")
            text = ""
            for pe in para.get("elements") or []:
                tr = pe.get("textRun")
                if tr:
                    text += tr.get("content", "")
            yield {
                "tabId": tab_id,
                "startIndex": el.get("startIndex"),
                "endIndex": el.get("endIndex"),
                "style": style,
                "text": text,
            }


def main() -> int:
    doc = json.loads(DOC_JSON.read_text(encoding="utf-8"))
    paras = list(iter_paragraphs(doc))

    keywords = [
        "13.2 Mode 2",
        "13 Scoring Modes",
        "13.1 Mode 1",
        "Figure 6",
        "Table 18",
        "Withdrawn",
        "five-metric",
        "Mode 2",
        "BTEA",
        "TA (Traceability",
        "10.6 Vector syntax",
        "2.3 Core architectural",
    ]
    print("=== KEY PARAGRAPHS ===")
    for p in paras:
        t = p["text"].strip()
        if any(k.lower() in t.lower() or k.lower() in p["style"].lower() for k in keywords):
            if t or "HEADING" in p["style"]:
                print(f"{p['startIndex']:6}-{p['endIndex']:6} [{p['style']}] {t[:120]}")

    # Find Section 13.2 range for deletion
    start = end = None
    for i, p in enumerate(paras):
        if p["text"].startswith("13.2 Mode 2"):
            start = p["startIndex"]
        if start and p["text"].startswith("14 OWASP Top 10"):
            end = p["startIndex"]
            break
    print(f"\nSection 13.2 delete range: {start} -> {end}")

    # Figure 6 caption
    for p in paras:
        if "Figure 6" in p["text"]:
            print(f"FIG6: {p['startIndex']}-{p['endIndex']} {p['text'][:80]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
