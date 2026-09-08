#!/usr/bin/env python3
"""Resume Phase 6-8 doc edits after partial run."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from apply_doc_remediation import (  # noqa: E402
    DOC_ID,
    HELPER,
    TAB_ID,
    find_index,
    get_doc,
    replace_all,
    verify_account,
)

PRESERVE = r"C:\Users\kenhu\.claude\skills\gws-google-doc-review\scripts\preserve_comment_span.py"
CALC_SHA = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
PYTEST_COUNT = "127"
APOLLO_URL = "https://www.apolloresearch.ai/research/claude-sonnet-3-7-evaluation-awareness"
NGUYEN_URL = "https://arxiv.org/abs/2507.01786"
NIST_800_53 = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"

ASI06_METRIC_RATIONALE = (
    "Synthetic reference fixture (informative). The ASI06 example in "
    "`examples/asi06-example.json` is a schema-valid calculator fixture, not a "
    "field measurement. Mode 1 AIVSS = CVSS-BTE only; no extended severity path. "
    "Metric-by-metric rationale for this fixture:\n"
    "LC:D — attacker text reaches a privileged tool path without mediation.\n"
    "CP:C — poisoned context persists in durable stores across sessions.\n"
    "AP:L — compromised context crosses to sibling agents or tenants.\n"
    "SR:R — production-equivalent fixture: 30/30 successes, Wilson LB 0.917.\n"
    "EX:W — dynamic/unvetted extension surface on the path.\n"
    "PT:H — unapproved provider/model routing without integrity pin.\n"
    "CA:M — hard ceiling exists but aggregate coverage is incomplete.\n"
    "TD:H — ordered actions and affected principals cannot be reconstructed.\n"
)

AIVSS_P_RULES = (
    "AIVSS-P is not monetary loss. It is an organization-internal priority index "
    "(Section 16) combining technical severity, business criticality, deployment "
    "reach, and likelihood — not dollar loss, revenue at risk, or regulatory fines. "
    "Unknown inputs are not zero: missing likelihood, reach, or criticality MUST "
    "be recorded as unknown (X) and excluded from the numeric index until resolved; "
    "substituting zero inflates priority incorrectly.\n"
    "Qualitative to numeric mapping (organization-local, publish internally): "
    "Criticality {Low=1, Medium=2, High=3}; Reach {Single=1, Department=2, "
    "Enterprise=3}; Likelihood uses NIST SP 800-30 Rev. 1 ordinal bands mapped to "
    "0.2 / 0.5 / 0.8 for qualitative {Low, Medium, High} before indexing.\n"
    "Conflict rules. When AIVSS-P band says Immediate but BOD baseline says 60D, "
    "the BOD `cisa:BOD2604:1.0.0` outcome is the federal compliance obligation; "
    "AIVSS-P informs internal sprint planning only. Release gates (Section 19.2) "
    "evaluate in order; the most-restrictive applicable gate wins. A waiver records "
    "a deployment exception — it is not a product roadmap commitment and does not "
    "change stored vectors or scores.\n"
)

RELEASE_GATES = (
    "Release gate evaluation (informative). Gates MUST be evaluated in listed "
    "order; when multiple gates fire, the most-restrictive outcome wins (block > "
    "remediate > monitor). TD (Traceability Deficit) — not TA — is the mandatory "
    "traceability metric for gate conditions. Waivers document compensating controls "
    "and expiry; they do not substitute for a remediation roadmap. No Mode 2 or "
    "candidate_adjusted triggers apply — withdrawn from normative scope.\n"
)


def batch_update_file(revision_id: str, requests: list[dict], label: str) -> None:
    payload = {"requests": requests, "writeControl": {"requiredRevisionId": revision_id}}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tf:
        json.dump(payload, tf)
        tf_path = tf.name
    proc = subprocess.run(
        [
            sys.executable,
            HELPER,
            "run",
            "--",
            "docs",
            "documents",
            "batchUpdate",
            "--params",
            json.dumps({"documentId": DOC_ID}),
            "--json",
            Path(tf_path).read_text(encoding="utf-8"),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    Path(tf_path).unlink(missing_ok=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout[-4000:])
    print(f"applied {label}: {len(requests)} requests")


def apply(old: str, new: str, label: str) -> None:
    if not old or old == new:
        return
    doc = get_doc()
    rev = doc["revisionId"]
    try:
        batch_update_file(rev, [replace_all(old, new, True)], label)
    except RuntimeError as exc:
        if "No occurrences" in str(exc):
            print(f"skip {label}")
        else:
            raise
    time.sleep(0.35)


def insert_after(anchor: str, text: str, label: str) -> None:
    doc = get_doc()
    rev = doc["revisionId"]
    idx = find_index(doc, anchor)
    batch_update_file(
        rev,
        [{"insertText": {"location": {"index": idx, "tabId": TAB_ID}, "text": text}}],
        label,
    )
    time.sleep(0.35)


def main() -> int:
    verify_account()
    apollo_old = (
        'Apollo Research has documented growing "evaluation awareness" in frontier reasoning models, '
        "and reports that while today's models are unlikely to be using this awareness to hide "
        "misalignment, they are becoming rapidly more situationally aware and strategic in ways that "
        "would make such concealment possible. Recent white-box interpretability work has further "
        "observed that this awareness is beginning to shift from verbalized chain-of-thought reasoning "
        "toward forms that leave no trace in visible reasoning at all"
    )
    apollo_new = (
        "Apollo Research (2025-03-17) reported evaluation-awareness behaviours in Claude Sonnet 3.7 "
        f"({APOLLO_URL}); Nguyen et al. (arXiv:2507.01786v2) document white-box evidence of "
        f"latent reasoning not reflected in visible chain-of-thought ({NGUYEN_URL}). These are "
        "reconstructable external records cited for traceability risk context; they do not prove "
        "deployment-level untraceability in every agent system"
    )
    replacements = [
        (
            "Band cut-points (p90 / p65 / p35 of a uniform grid, n = 10,980, severity 4.0–10.0): Immediate ≥ 78, This sprint ≥ 64, Scheduled ≥ 53, Backlog below 53. The grid over-represents high-severity findings relative to a real portfolio; organizations SHOULD recalibrate cut-points against their own assessment corpus (Section 22).",
            "Band cut-points are provisional: p90 / p65 / p35 of an artificial uniform grid (n = 10,980, severity 4.0–10.0) yield Immediate >= 78, This sprint >= 64, Scheduled >= 53, Backlog < 53. This grid over-represents high-severity findings; organizations MUST recalibrate cut-points against their own corpus (Section 22) before using bands for release decisions.",
            "percentile bands",
        ),
        (
            "Release gates translate AIVSS outputs into allow / remediate / block decisions. Gates MUST be defined by the deploying organization; the table below is a recommended starting point.",
            "Release gates translate AIVSS outputs into allow / remediate / block decisions. Gates MUST be defined by the deploying organization; evaluate gates in order with most-restrictive wins. The table below is a recommended starting point.",
            "release gates intro",
        ),
        (
            "Table 23 recommends release-blocking conditions keyed to AIVSS score bands, Agentic AI Effect Class, TD level, and specific ASI/SR combinations — translating severity into deploy-or-hold guidance.",
            "Table 23 recommends release-blocking conditions keyed to Mode 1 AIVSS score bands, Agentic AI Effect Class, TD level (not TA), and specific ASI/SR combinations. Waivers record exceptions; they are not roadmaps. No Mode 2 triggers.",
            "Table 23",
        ),
        (
            "Normative pin: branch remove-mode2-candidate-adjusted, commit 238309c1048926443cc339503049e639bcf23fc6.",
            f"Normative pin: branch remove-mode2-candidate-adjusted, commit {CALC_SHA}.",
            "ref pin",
        ),
        ("# 93 tests", f"# {PYTEST_COUNT} pytest", "93 tests"),
        (apollo_old, apollo_new, "apollo citations"),
    ]
    for old, new, label in replacements:
        apply(old, new, label)

    doc = get_doc()
    body = ""
    tab = (doc.get("tabs") or [{}])[0]
    for el in ((tab.get("documentTab") or {}).get("body") or {}).get("content") or []:
        para = el.get("paragraph")
        if para:
            for pe in para.get("elements") or []:
                tr = pe.get("textRun")
                if tr:
                    body += tr.get("content", "")

    if "AIVSS-P is not monetary loss" not in body:
        insert_after(
            "Each quantity is priced exactly once. Exploitation evidence belongs to the decision track (Section 12), not AIVSS-P.",
            "\n" + AIVSS_P_RULES,
            "AIVSS-P rules",
        )
    if "Metric-by-metric rationale" not in body:
        insert_after("Input vector:", "\n" + ASI06_METRIC_RATIONALE, "ASI06 metrics")
    if "Release gate evaluation" not in body:
        insert_after("Table 23: Recommended Release Gates", "\n" + RELEASE_GATES, "release gates")

    if "Apollo Research, 2025" not in body:
        insert_after(
            "(Householder et al., 2019). SSVC: Stakeholder-Specific Vulnerability Categorization. https://certcc.github.io/SSVC/\n",
            f"(Apollo Research, 2025). Claude Sonnet 3.7 Evaluation Awareness (2025-03-17). {APOLLO_URL}\n",
            "Apollo ref",
        )
    if "Nguyen et al." not in body:
        insert_after(
            f"(Apollo Research, 2025). Claude Sonnet 3.7 Evaluation Awareness (2025-03-17). {APOLLO_URL}",
            f"\n(Nguyen et al., 2025). Latent reasoning traces in language models. arXiv:2507.01786v2. {NGUYEN_URL}\n",
            "Nguyen ref",
        )
    if "SP 800-53" not in body:
        insert_after(
            "(NIST, 2012). SP 800-30 Rev. 1 — Guide for Conducting Risk Assessments. https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final\n",
            f"(NIST, 2020). SP 800-53 Rev. 5 — Security and Privacy Controls. {NIST_800_53}\n",
            "NIST 800-53",
        )

    # hyperlinks + mis-styled headings from phase678 helpers
    subprocess.run([sys.executable, str(REPO / "scripts" / "apply_doc_phase678_finish.py")], check=False)
    subprocess.run([sys.executable, str(REPO / "scripts" / "final_scan_counts.py")], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
