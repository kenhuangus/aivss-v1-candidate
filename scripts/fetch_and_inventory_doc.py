#!/usr/bin/env python3
"""Fetch AIVSS Google Doc and inventory Mode 2 / candidate_adjusted mentions."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

DOC_ID = "1SIO6yN1x4XXTnclLeEsFFHnqzRR-3SOvUJTHF7CGRpI"
HELPER = r"C:\Users\kenhu\.claude\skills\gws-google-doc-review\scripts\gws_profile.py"
OUT_DIR = Path(r"C:\Users\kenhu\AppData\Local\Temp\aivss-v1-candidate\doc-work")


def gws(*args: str) -> dict:
    proc = subprocess.run(
        [sys.executable, HELPER, "run", "--", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"gws failed: {proc.stderr or proc.stdout[-3000:]}")
    text = proc.stdout
    start = text.find("{")
    if start < 0:
        start = text.find("[")
    if start < 0:
        raise RuntimeError(f"no JSON in output:\n{text[:2000]}")
    return json.loads(text[start:])


def extract_text_from_body(body: dict) -> str:
    parts: list[str] = []
    for el in body.get("content") or []:
        para = el.get("paragraph")
        if not para:
            continue
        style = (para.get("paragraphStyle") or {}).get("namedStyleType", "")
        line = ""
        for pe in para.get("elements") or []:
            tr = pe.get("textRun")
            if tr:
                line += tr.get("content", "")
        if line.strip():
            parts.append(f"[{style}] {line.rstrip()}")
    return "\n".join(parts)


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    about = gws("drive", "about", "get", "--params", json.dumps({"fields": "user(emailAddress,displayName)"}))
    email = (about.get("user") or {}).get("emailAddress")
    print(f"GWS_EMAIL: {email}")
    if email != "kenhuangus@gmail.com":
        print("STOP: wrong account")
        return 1

    doc = gws(
        "docs",
        "documents",
        "get",
        "--params",
        json.dumps({"documentId": DOC_ID, "includeTabsContent": True}),
    )
    (OUT_DIR / "doc-full.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")

    meta = {
        "documentId": doc.get("documentId"),
        "title": doc.get("title"),
        "revisionId": doc.get("revisionId"),
    }
    print(json.dumps(meta, indent=2))

    # Plain text from all tabs
    all_text = ""
    headings: list[str] = []
    for tab in doc.get("tabs") or []:
        tab_id = (tab.get("tabProperties") or {}).get("tabId", "?")
        tab_title = (tab.get("tabProperties") or {}).get("title", "?")
        body = (tab.get("documentTab") or {}).get("body") or {}
        tab_text = extract_text_from_body(body)
        all_text += f"\n=== TAB {tab_title} ({tab_id}) ===\n" + tab_text + "\n"
        for line in tab_text.splitlines():
            if line.startswith("[HEADING"):
                headings.append(line)

    (OUT_DIR / "doc-plain.txt").write_text(all_text, encoding="utf-8")
    (OUT_DIR / "headings.txt").write_text("\n".join(headings), encoding="utf-8")

    # Inventory patterns
    patterns = {
        "Mode 2": r"Mode\s*2",
        "Mode2": r"Mode2",
        "BTEA": r"BTEA",
        "macrovector promotion": r"macrovector\s+promotion|MacroVector\s+promotion|MacroVector\s+EQ",
        "EQ4 promotion": r"EQ4\s+promotion|EQ\s*4\s+promotion",
        "candidate_adjusted": r"candidate_adjusted|candidate adjusted",
        "candidate adjustment": r"candidate\s+adjustment",
        "experimental_macrovector": r"experimental_macrovector|experimental macrovector",
        "not arithmetic uplift": r"not\s+arithmetic\s+uplift|arithmetic\s+uplift",
        "ASI06 9.0/9.1 Mode 2": r"ASI06.*Mode\s*2|9\.0.*Mode\s*2|9\.1.*Mode\s*2",
        "TA vs TD": r"\bTA\b",
        "five-metric": r"five[- ]metric|5[- ]metric",
        "eight-metric": r"eight[- ]metric|8[- ]metric",
    }

    inventory_lines: list[str] = ["=== INVENTORY ==="]
    for name, pat in patterns.items():
        matches = list(re.finditer(pat, all_text, re.IGNORECASE))
        inventory_lines.append(f"\n{name}: {len(matches)} hits")
        for m in matches[:5]:
            start = max(0, m.start() - 60)
            end = min(len(all_text), m.end() + 60)
            snippet = all_text[start:end].replace("\n", " ")
            inventory_lines.append(f"  ...{snippet}...")

    inventory_text = "\n".join(inventory_lines)
    (OUT_DIR / "inventory-after.txt").write_text(
        f"GWS_EMAIL: {email}\n{json.dumps(meta, indent=2)}\n\n{inventory_text}\n",
        encoding="utf-8",
    )
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(inventory_text)

    print(f"\n=== HEADINGS ({len(headings)}) ===")
    for h in headings[:40]:
        print(h)
    if len(headings) > 40:
        print(f"... and {len(headings) - 40} more")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
