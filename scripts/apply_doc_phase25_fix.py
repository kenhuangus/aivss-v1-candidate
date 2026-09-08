#!/usr/bin/env python3
"""Fix MacroVector EQ mapping, arithmetic, heading styles, links, C02, appendix."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from apply_doc_remediation import (  # noqa: E402
    DOC_ID,
    TAB_ID,
    batch_update,
    get_doc,
    replace_all,
    verify_account,
)

APPENDIX_REPORT = REPO / "examples" / "appendix-a-mode1-report.json"

FIRST_SPEC = "https://www.first.org/cvss/v4.0/specification-document"
CISA_FAQ = (
    "https://www.cisa.gov/news-events/directives/"
    "bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
)
FEDRAMP_NTC = "https://www.fedramp.gov/notices/0014/"

MACROVECTOR_EQ_BLOCK_OLD = (
    "Accessible text equivalent of FIRST CVSS v4.0 MacroVector Table 4 "
    "(equivalence groups EQ1–EQ6). Editorial note: the published figure is an "
    "image; this table is the normative text substitute.\n\n"
    "EQ1 — Attack Vector (AV): N / A / L / P\n"
    "EQ2 — Attack Complexity (AC): L / H\n"
    "EQ3 — Attack Requirements (AT) and Vulnerable-System impacts (VC, VI, VA) jointly\n"
    "EQ4 — Privileges Required (PR) and User Interaction (UI) jointly\n"
    "EQ5 — Exploit Maturity (E) from the Threat metric group\n"
    "EQ6 — Subsequent-System impacts (SC, SI, SA) plus Environmental modifiers "
    "(Modified Base, Modified Threat, Modified Environmental, CR, IR, AR)\n\n"
    "Base metric combination count: 4 × 2 × 2 × 3 × 3 × 36 = 104,976 ordered "
    "Base vectors. MacroVector equivalence collapses these into 270 expert-ranked "
    "severity classes (~15M full CVSS v4.0 vectors when Threat and Environmental "
    "groups vary). The earlier draft figure of 2,048 Base combinations omitted "
    "the full EQ3/EQ5/EQ6 mapping.\n"
)

MACROVECTOR_EQ_BLOCK_NEW = (
    "Accessible text equivalent of FIRST CVSS v4.0 MacroVector Table 4 "
    "(equivalence groups EQ1–EQ6). Editorial note: the published figure is an "
    "image; this table is the normative text substitute. Source: FIRST CVSS v4.0 "
    f"Specification Document, Section 8.2 and Table 29 ({FIRST_SPEC}).\n\n"
    "EQ1 — Attack Vector (AV), Privileges Required (PR), and User Interaction (UI) jointly\n"
    "EQ2 — Attack Complexity (AC) and Attack Requirements (AT) jointly\n"
    "EQ3 — Vulnerable-System impacts (VC, VI, VA) jointly\n"
    "EQ4 — Subsequent-System impacts (SC, SI, SA) jointly\n"
    "EQ5 — Exploit Maturity (E) from the Threat metric group\n"
    "EQ6 — Vulnerable-System impacts (VC, VI, VA) plus Security Requirements "
    "(CR, IR, AR) per FIRST Table 29\n\n"
    "Base metric combination count: 4 × 2 × 2 × 3 × 3 × 3\u2076 = 104,976 ordered "
    "Base vectors (AV×AC×AT×PR×UI×six impact metrics at three levels each). "
    "MacroVector equivalence collapses these 104,976 Base combinations into 270 "
    "expert-ranked severity classes; the full CVSS v4.0 vector space is far larger "
    "(~15M vectors) when Threat and Environmental groups vary. The earlier draft "
    "figure of 2,048 Base combinations omitted the full EQ3/EQ5/EQ6 mapping.\n"
)

ENV_OLD = (
    "Environmental metrics adjust severity for a specific deployment. CVSS v4.0 "
    "defines Base (B), Threat (BT), and Environmental (BE) groups; CVSS-BTE is "
    "Base + Threat + Environmental without organizational Security Requirements "
    "(Modified Base / Modified Threat / Modified Environmental / CR / IR / AR). "
    "AIVSS-P is separate from CVSS environmental tailoring. Level 1 conformance "
    "does not require organizational modifiers."
)

ENV_NEW = (
    "Environmental metrics adjust severity for a specific deployment. In CVSS v4.0, "
    "the Environmental metric group includes Modified Base, Modified Threat, Modified "
    "Environmental, and Security Requirements (CR, IR, AR) — assessors MUST NOT "
    "treat Environmental as a stripped subset that omits Security Requirements. "
    "CVSS-BTE is the score from Base + Threat + Environmental groups present in the "
    "vector (including Exploit Maturity E from Threat). Level 1 conformance does not "
    "require assessors to supply organizational modifiers; omitted values default per "
    "FIRST rules. AIVSS-P is an organization-internal priority index (Section 16) and "
    "MUST NOT be conflated with CVSS Environmental tailoring."
)

CVSS_BTE_DEF_OLD = (
    "Definition — CVSS-BTE. The CVSS v4.0 score computed from the Base, Threat, "
    "and Environmental metric groups, excluding organizational (Modified Base / "
    "Modified Threat / Security Requirements) overlays. Computed using proper CVSS "
    "v4.0 interpolation per FIRST `cvss_lookup.js` (FIRST, 2024)."
)

CVSS_BTE_DEF_NEW = (
    "Definition — CVSS-BTE. The CVSS v4.0 score computed from Base + Threat + "
    "Environmental metric groups in the supplied vector — including Exploit Maturity "
    "(E) and any Environmental modifiers (Modified Base/Threat/Environmental and "
    "Security Requirements CR/IR/AR) when assessors include them. Computed using "
    "proper CVSS v4.0 interpolation per FIRST `cvss_lookup.js` (FIRST, 2024)."
)

CVSS_BTE_GLOSS_OLD = (
    "CVSS-BTE. The CVSS score computed from Base + Threat + Environmental metric "
    "groups, without organizational (Modified Base / Modified Threat / Modified "
    "Environmental / Security Requirements) overlays. This is the standard \"full\" "
    "CVSS score before per-organization tailoring. AIVSS uses proper CVSS v4.0 "
    "interpolation per FIRST `cvss_lookup.js` (FIRST, 2024), not merely the "
    "MacroVector ceiling."
)

CVSS_BTE_GLOSS_NEW = (
    "CVSS-BTE. The CVSS score computed from Base + Threat + Environmental metric "
    "groups in the supplied vector. Environmental includes Modified Base/Threat/"
    "Environmental and Security Requirements (CR/IR/AR) when present; Level 1 "
    "assessments typically omit organizational modifiers. AIVSS uses proper CVSS "
    "v4.0 interpolation per FIRST `cvss_lookup.js` (FIRST, 2024), not merely the "
    "MacroVector ceiling."
)

SEVERITY_SCORE_OLD = (
    "The severity score is the primary output of Mode 1 (normative) scoring. It "
    "equals CVSS-BTE — the CVSS score computed from Base, Threat, and Environmental "
    "metric groups without organizational modifiers (Section 3.2)."
)

SEVERITY_SCORE_NEW = (
    "The severity score is the primary output of Mode 1 (normative) scoring. It "
    "equals CVSS-BTE — the CVSS score computed from Base, Threat, and Environmental "
    "metric groups in the supplied vector (Section 3.2). Level 1 conformance does "
    "not require organizational Environmental modifiers."
)

HEADING_PREFIXES = (
    "Missing-metadata FAQ rule",
    CISA_FAQ,
    "FedRAMP policy milestones",
    FEDRAMP_NTC,
    "Assessment pipeline order (normative):",
    "Reference calculator:",
    "Normative pin:",
    "Install:",
    "Example: aivss-calc assess",
    "Issues and PRs against",
)

LINK_TARGETS = (
    (FIRST_SPEC, FIRST_SPEC),
    (CISA_FAQ, CISA_FAQ),
    (FEDRAMP_NTC, FEDRAMP_NTC),
)


def apply_replacement(old: str, new: str, label: str) -> None:
    if old == new:
        return
    doc = get_doc()
    rev = doc["revisionId"]
    try:
        batch_update(rev, [replace_all(old, new, True)], label)
    except RuntimeError as exc:
        if "No occurrences" in str(exc) or "not found" in str(exc).lower():
            print(f"skip {label}: not found")
        else:
            raise
    time.sleep(0.35)


def iter_paragraphs(doc: dict):
    tab = (doc.get("tabs") or [{}])[0]
    for el in ((tab.get("documentTab") or {}).get("body") or {}).get("content") or []:
        para = el.get("paragraph")
        if not para:
            continue
        text = ""
        for pe in para.get("elements") or []:
            tr = pe.get("textRun")
            if tr:
                text += tr.get("content", "")
        style = (para.get("paragraphStyle") or {}).get("namedStyleType", "")
        yield el["startIndex"], el["endIndex"], text, style


def fix_misstyled_headings() -> None:
    doc = get_doc()
    rev = doc["revisionId"]
    requests: list[dict] = []
    for start, end, text, style in iter_paragraphs(doc):
        stripped = text.strip()
        if not stripped:
            continue
        if style in ("HEADING_2", "HEADING_3") and any(
            stripped.startswith(p) for p in HEADING_PREFIXES
        ):
            requests.append(
                {
                    "updateParagraphStyle": {
                        "range": {"startIndex": start, "endIndex": end, "tabId": TAB_ID},
                        "paragraphStyle": {"namedStyleType": "NORMAL_TEXT"},
                        "fields": "namedStyleType",
                    }
                }
            )
    if not requests:
        print("no mis-styled headings found")
        return
    for i in range(0, len(requests), 8):
        doc = get_doc()
        rev = doc["revisionId"]
        batch_update(rev, requests[i : i + 8], f"heading styles {i // 8 + 1}")
        time.sleep(0.35)


def apply_hyperlinks() -> None:
    doc = get_doc()
    rev = doc["revisionId"]
    requests: list[dict] = []
    for start, end, text, _style in iter_paragraphs(doc):
        for url, target in LINK_TARGETS:
            pos = 0
            while True:
                idx = text.find(url, pos)
                if idx < 0:
                    break
                rs = start + idx
                re_ = rs + len(url)
                requests.append(
                    {
                        "updateTextStyle": {
                            "range": {
                                "startIndex": rs,
                                "endIndex": re_,
                                "tabId": TAB_ID,
                            },
                            "textStyle": {"link": {"url": target}},
                            "fields": "link",
                        }
                    }
                )
                pos = idx + len(url)
    if not requests:
        print("no hyperlink targets found")
        return
    for i in range(0, len(requests), 10):
        doc = get_doc()
        rev = doc["revisionId"]
        batch_update(rev, requests[i : i + 10], f"hyperlinks {i // 10 + 1}")
        time.sleep(0.35)


def fix_truncated_appendix() -> None:
    if not APPENDIX_REPORT.exists():
        print("skip appendix: file missing")
        return
    doc = get_doc()
    body = ""
    for _start, _end, text, _style in iter_paragraphs(doc):
        body += text
    payload = json.dumps(
        json.loads(APPENDIX_REPORT.read_text(encoding="utf-8")),
        indent=2,
        sort_keys=False,
    )
    if payload.strip() in body and '"overlay_status": "experimental-uncalibrated"' in body:
        print("appendix JSON already complete")
        return

    marker = "Complete Mode 1 report (schema-valid"
    anchor = "Validate structure against `schemas/aivss-report-v1.0.json`."
    start_idx = end_idx = None
    for el_start, _el_end, text, _style in iter_paragraphs(doc):
        if marker in text and start_idx is None:
            start_idx = el_start
        if anchor in text and start_idx is not None:
            end_idx = el_start
            break
    if start_idx is None or end_idx is None:
        raise RuntimeError("appendix truncation markers not found")

    block = (
        "Complete Mode 1 report (schema-valid; examples/appendix-a-mode1-report.json):\n\n"
        f"{payload}\n\n"
    )
    doc = get_doc()
    rev = doc["revisionId"]
    batch_update(
        rev,
        [
            {
                "deleteContentRange": {
                    "range": {
                        "startIndex": start_idx,
                        "endIndex": end_idx,
                        "tabId": TAB_ID,
                    }
                }
            }
        ],
        "delete truncated appendix JSON",
    )
    time.sleep(0.35)

    doc = get_doc()
    insert_at = start_idx
    chunk_size = 2800
    for i in range(0, len(block), chunk_size):
        chunk = block[i : i + chunk_size]
        doc = get_doc()
        rev = doc["revisionId"]
        batch_update(
            rev,
            [
                {
                    "insertText": {
                        "location": {"index": insert_at, "tabId": TAB_ID},
                        "text": chunk,
                    }
                }
            ],
            f"insert appendix JSON chunk {i // chunk_size + 1}",
        )
        insert_at += len(chunk)
        time.sleep(0.35)


def main() -> int:
    verify_account()
    replacements = [
        (MACROVECTOR_EQ_BLOCK_OLD, MACROVECTOR_EQ_BLOCK_NEW, "MacroVector EQ table"),
        (
            "The 270 classes collapse 104,976 ordered Base metric combinations (4×2×2×3×3×36)",
            "The 270 classes collapse 104,976 ordered Base metric combinations (4×2×2×3×3×3\u2076)",
            "MacroVector inline arithmetic",
        ),
        ("× 3 × 3 × 36 = 104,976", "× 3 × 3 × 3\u2076 = 104,976", "residual ×36"),
        (ENV_OLD, ENV_NEW, "Environmental C02"),
        (CVSS_BTE_DEF_OLD, CVSS_BTE_DEF_NEW, "CVSS-BTE definition"),
        (CVSS_BTE_GLOSS_OLD, CVSS_BTE_GLOSS_NEW, "CVSS-BTE glossary"),
        (SEVERITY_SCORE_OLD, SEVERITY_SCORE_NEW, "severity score paragraph"),
        (
            "(FIRST, 2024). CVSS v4.0 Specification Document, Section 8.2 MacroVectors. "
            "https://www.first.org/cvss/v4.0/specification-document",
            "(FIRST, 2024). CVSS v4.0 Specification Document, Section 8.2 MacroVectors. "
            f"{FIRST_SPEC}",
            "references FIRST spec (noop if linked later)",
        ),
    ]
    for old, new, label in replacements:
        apply_replacement(old, new, label)

    fix_truncated_appendix()
    fix_misstyled_headings()
    apply_hyperlinks()

    subprocess.run(
        [sys.executable, str(REPO / "scripts" / "fetch_and_inventory_doc.py")],
        check=True,
    )
    print("phase25 fix complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
