#!/usr/bin/env python3
"""Insert ref impl pin only."""
import json, subprocess, sys, time
from apply_doc_remediation import DOC_ID, HELPER, TAB_ID, REF_IMPL_BODY, batch_update, find_index, get_doc, verify_account

def main():
    verify_account()
    doc = get_doc()
    tab = (doc.get("tabs") or [{}])[0]
    body_text = ""
    for el in ((tab.get("documentTab") or {}).get("body") or {}).get("content") or []:
        para = el.get("paragraph")
        if not para:
            continue
        body_text += "".join((pe.get("textRun") or {}).get("content", "") for pe in para.get("elements") or [])
    if body_text.count("Normative pin: branch remove-mode2-candidate-adjusted") >= 1:
        print("already inserted")
        return 0
    rev = doc["revisionId"]
    idx = None
    for el in ((tab.get("documentTab") or {}).get("body") or {}).get("content") or []:
        para = el.get("paragraph")
        if not para:
            continue
        text = "".join((pe.get("textRun") or {}).get("content", "") for pe in para.get("elements") or [])
        if "18 Reference Implementation" in text:
            idx = el["endIndex"]
            break
    if idx is None:
        print("heading not found")
        return 1
    batch_update(rev, [{"insertText": {"location": {"index": idx, "tabId": TAB_ID}, "text": REF_IMPL_BODY}}], "insert ref impl pin")
    return 0

if __name__ == "__main__":
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
    raise SystemExit(main())
