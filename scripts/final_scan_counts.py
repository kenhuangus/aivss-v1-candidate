#!/usr/bin/env python3
"""Final remediation scan counts for AIVSS Google Doc."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

DOC_ID = "1SIO6yN1x4XXTnclLeEsFFHnqzRR-3SOvUJTHF7CGRpI"
HELPER = r"C:\Users\kenhu\.claude\skills\gws-google-doc-review\scripts\gws_profile.py"
OUT = Path(__file__).resolve().parents[1] / "doc-work" / "doc-plain.txt"


def gws(*args: str) -> dict:
    proc = subprocess.run(
        [sys.executable, HELPER, "run", "--", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout[-3000:])
    text = proc.stdout
    start = text.find("{")
    if start < 0:
        start = text.find("[")
    return json.loads(text[start:])


def extract_all_text(doc: dict) -> str:
    parts: list[str] = []
    for tab in doc.get("tabs") or []:
        body = (tab.get("documentTab") or {}).get("body") or {}
        for el in body.get("content") or []:
            para = el.get("paragraph")
            if para:
                for pe in para.get("elements") or []:
                    tr = pe.get("textRun")
                    if tr:
                        parts.append(tr.get("content", ""))
            table = el.get("table")
            if table:
                for row in table.get("tableRows") or []:
                    for cell in row.get("tableCells") or []:
                        for cel in cell.get("content") or []:
                            p = cel.get("paragraph")
                            if p:
                                for pe in p.get("elements") or []:
                                    tr = pe.get("textRun")
                                    if tr:
                                        parts.append(tr.get("content", ""))
    return "".join(parts)


def count_mode2_outside_withdrawal(text: str) -> int:
    n = 0
    for line in text.splitlines():
        if "Mode 2" not in line:
            continue
        low = line.lower()
        if any(
            x in low
            for x in (
                "withdrawn",
                "formerly",
                "remove-mode2-candidate",
                "no mode 2",
                "not mode 2",
                "withdrawn extended",
            )
        ):
            continue
        n += 1
    return n


def count_candidate_adjusted_outside_withdrawal(text: str) -> int:
    n = 0
    for m in re.finditer(r"candidate_adjusted|candidate adjusted", text, re.I):
        start = max(0, m.start() - 120)
        ctx = text[start : m.end() + 40].lower()
        if "withdrawn" in ctx or "formerly" in ctx or "removed" in ctx:
            continue
        n += 1
    return n


def main() -> int:
    about = gws("drive", "about", "get", "--params", json.dumps({"fields": "user(emailAddress)"}))
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
    text = extract_all_text(doc)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")

    counts = {
        "Mode2": count_mode2_outside_withdrawal(text),
        "candidate_adjusted": count_candidate_adjusted_outside_withdrawal(text),
        "TA:": len(re.findall(r"\bTA:[HML]\b", text)),
        "five-metric": len(re.findall(r"five[- ]metric|5[- ]metric", text, re.I)),
        "93_tests": len(re.findall(r"93\s+tests?", text, re.I)),
        "August7": text.count("August 7"),
        "December7": text.count("December 7"),
    }
    print("=== FINAL SCAN COUNTS ===")
    for k, v in counts.items():
        print(f"{k}={v}")
    print(
        f"FINAL_SCAN: Mode2={counts['Mode2']} candidate_adjusted={counts['candidate_adjusted']} "
        f"TA:={counts['TA:']} five-metric={counts['five-metric']} 93_tests={counts['93_tests']} "
        f"August7={counts['August7']} December7={counts['December7']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
