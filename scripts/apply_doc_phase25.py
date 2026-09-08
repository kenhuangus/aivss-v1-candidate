#!/usr/bin/env python3
"""Apply AIVSS v1 production remediation Phases 2-5 to the Google Doc."""
from __future__ import annotations

import json
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from apply_doc_remediation import (  # noqa: E402
    DOC_ID,
    HELPER,
    TAB_ID,
    batch_update,
    find_index,
    get_doc,
    gws,
    replace_all,
    verify_account,
)

APPENDIX_REPORT = REPO / "examples" / "appendix-a-mode1-report.json"
PYTEST_COUNT = "127"

MACROVECTOR_EQ_TABLE = (
    "Accessible text equivalent of FIRST CVSS v4.0 MacroVector Table 4 "
    "(equivalence groups EQ1–EQ6). Editorial note: the published figure is an "
    "image; this table is the normative text substitute. Source: FIRST CVSS v4.0 "
    "Specification Document, Section 8.2 and Table 29 "
    "(https://www.first.org/cvss/v4.0/specification-document).\n\n"
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

FEDRAMP_MILESTONES = (
    "FedRAMP policy milestones (NTC-0014, Aug 7 2026): CSPs must align with BOD "
    "26-04 by Aug 7 2026; BOD remediation timelines begin Dec 7 2026 for "
    "FedRAMP-authorized systems; CSP grace period ends Mar 7 2027. June 10 2026 "
    "is the BOD issuance date for FCEB agencies, not the sole deadline regime for "
    "all federal cloud workloads.\n"
    "https://www.fedramp.gov/notices/0014/\n\n"
)

FAQ_60D_RULE = (
    "Missing-metadata FAQ rule (CISA BOD 26-04 implementation guidance): for a "
    "non-KEV CVE where CISA has published neither Automatable nor Technical "
    "Impact, the remediation timeline is 60 days — not a table lookup using "
    "default no/total (which can wrongly yield 14 days when the asset is "
    "publicly exposed). Unknown Publicly Exposed defaults to Yes. KEV-listed "
    "CVEs require published Vulnrichment values. SR/CVSS inference is an "
    "informative overlay only and MUST NOT be labelled unmodified BOD.\n"
    "https://www.cisa.gov/news-events/directives/"
    "bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk\n\n"
)

CONFORMANCE_NOTE = (
    "Conformance matrix (normative). Level 1 requires cvss_vector and, when "
    "present, a complete eight-metric aivss_vector (LC CP AP SR EX PT CA TD). "
    "Missing, partial, or unknown (X) metric values are not equivalent to "
    "all-benign: a missing profile is not A0. Effect class A0 is assigned only "
    "from evaluated LC:N + CP:N + AP:N + SR:U values. Level 2 adds the SSVC/BOD "
    "decision track with baseline CISA table lookup separate from any AIVSS "
    "overlay.\n\n"
)

PIPELINE_ORDER = (
    "Assessment pipeline order (normative): (1) resolve CVSS vector including "
    "Threat Exploit Maturity (E) before severity interpolation; (2) score "
    "Agentic AI Profile independently from cvss_vector; (3) classify Agentic "
    "AI Effect Class from LC–SR only; (4) resolve SSVC/BOD timeline on its own "
    "inputs; (5) apply optional A2 overlay. Reassess when dated inputs change "
    "(EPSS date, Vulnrichment refresh, exposure inventory).\n\n"
)


def text_replacements() -> list[tuple[str, str, bool]]:
    return [
        # Phase 2 — paths and test count
        (
            "Example files in `tools/aivss-calc/examples/`.",
            f"Example files in `examples/` at the repository root (`aivss_calc/` package). "
            f"Reference test suite: {PYTEST_COUNT} pytest cases.",
            True,
        ),
        (
            "Issues and PRs against `tools/aivss-calc` and schema files",
            "Issues and PRs against the `aivss_calc` package and schema files",
            True,
        ),
        (
            "reference calculator (`tools/aivss-calc`)",
            "reference calculator (`aivss_calc`, repository root)",
            True,
        ),
        (
            "`tools/aivss-calc` maintainers",
            "`aivss_calc` maintainers",
            True,
        ),
        (
            "Install with pip install -e package dev extras; run aivss-calc verify and pytest.",
            f"Install: `pip install -e \".[dev]\"` from the repository root; run `aivss-calc verify` and `pytest` ({PYTEST_COUNT} tests).",
            True,
        ),
        # Phase 3 — MacroVector / EQ
        (
            "MacroVector. CVSS v4.0 collapses the 2,048 possible Base metric combinations into 270 equivalence classes (MacroVectors), each assigned an expert-ranked severity score (FIRST, 2024). A MacroVector is identified by six equivalence-group indices EQ1–EQ6.",
            "MacroVector. CVSS v4.0 assigns every valid vector a MacroVector class — one of 270 expert-ranked equivalence groups (FIRST, 2024). A MacroVector is identified by six equivalence-group indices EQ1–EQ6. The 270 classes collapse 104,976 ordered Base metric combinations (4×2×2×3×3×3\u2076); full CVSS v4.0 vector space is far larger (~15M vectors) when Threat and Environmental groups vary.",
            True,
        ),
        (
            "Environmental metrics adjust severity for a specific deployment. AIVSS uses environmental metrics when computing CVSS-BTE but does not require organizational modifiers for conformance Level 1.",
            "Environmental metrics adjust severity for a specific deployment. In CVSS v4.0, the Environmental metric group includes Modified Base, Modified Threat, Modified Environmental, and Security Requirements (CR, IR, AR) — assessors MUST NOT treat Environmental as a stripped subset that omits Security Requirements. CVSS-BTE is the score from Base + Threat + Environmental groups present in the vector (including Exploit Maturity E from Threat). Level 1 conformance does not require assessors to supply organizational modifiers; omitted values default per FIRST rules. AIVSS-P is an organization-internal priority index (Section 16) and MUST NOT be conflated with CVSS Environmental tailoring.",
            True,
        ),
        (
            "E (Exploit Maturity). Set from the exploitation evidence ladder (Section 12.3): authoritative Active (KEV or Vulnrichment) → `E:A`; organization-observed Active (unverified) or PoC → `E:P`; no evidence → `E:U`.",
            "E (Exploit Maturity). Set from the exploitation evidence ladder per FIRST Table 12 (Section 12.3): authoritative Active (KEV or Vulnrichment) → `E:A`; organization-observed Active (unverified) or PoC → `E:P`; no affirmative evidence → `E:U`. Missing exploitation intelligence is not `E:U` by timeout — assessors must walk the ladder. `E:X` is reserved for assessments where Exploit Maturity cannot be resolved.",
            True,
        ),
        (
            "The selected rung sets CVSS `E` (Exploit Maturity) for the assessment: authoritative Active (items 1–2) → `E:A`; Active (unverified) or PoC (items 3–4) → `E:P`; None (item 5) → `E:U`.",
            "The selected rung sets CVSS `E` (Exploit Maturity) for the assessment per FIRST Table 12: authoritative Active (items 1–2) → `E:A`; Active (unverified) or PoC (items 3–4) → `E:P`; None (item 5) → `E:U` only when the ladder completes with no evidence. Missing intelligence does not default to `E:U`.",
            True,
        ),
        # Phase 4 — Effect class / conformance
        (
            "A0 means all metrics are at their benign values, or no Agentic AI Profile was supplied — in which case AIVSS equals CVSS-BTE exactly.",
            "A0 means LC:N, CP:N, AP:N, and SR:U from evaluated metric values. A missing Agentic AI Profile is not A0 and MUST NOT be substituted for an all-benign profile; when the profile is absent, effect class is not asserted and AIVSS equals CVSS-BTE.",
            True,
        ),
        (
            "- A0 (None) — LC:N and CP:N and AP:N and SR:U, or the Agentic AI metric group is absent",
            "- A0 (None) — LC:N and CP:N and AP:N and SR:U from evaluated values only (missing profile ≠ A0 / all-benign)",
            True,
        ),
        (
            "Figure 3 summarizes the boolean Agentic AI Effect Class ladder: A2 (substantial agentic amplification), A1 (present but not substantial), and A0 (no profile or all benign), including the rule that A2 may advance remediation by one SSVC outcome tier (Section 12.4).",
            "Figure 3 summarizes the boolean Agentic AI Effect Class ladder: A2 (substantial agentic amplification), A1 (present but not substantial), and A0 (all benign evaluated values only), including the rule that A2 may advance remediation by one SSVC outcome tier (Section 12.4).",
            True,
        ),
        (
            "If AT already captures stochasticity, do not also score SR (Section 9.3).",
            "If AT already captures stochasticity on this path, SR is N/A for that stochasticity — do not double-count (Section 9.3, Section 10.4). LC levels are mutually exclusive with explicit precedence; human approval without meaningful review does not reduce LC.",
            True,
        ),
        (
            "PR (Privileges Required). Score the agent's effective credential, not the human end-user's.",
            "PR (Privileges Required). Score attacker prerequisites — the agent's effective credential and reachable authority on this path, not the human end-user's session. Paired examples: stolen agent service account with DB write → PR:L or PR:H per reach; human SSO alone without agent credential → not PR for the agent path.",
            True,
        ),
        (
            "UI (User Interaction). If human approval is nominally required but routinely granted without meaningful review, the honest value is UI:N (no interaction required). In ASI09 Human–Agent Trust Exploitation, forged agent summaries that humans approve without review also imply UI:N for the underlying attack path.",
            "UI (User Interaction). UI measures required human participation on the attack path, not reviewer diligence. Rubber-stamp approval without meaningful review → UI:N. ASI09 forged summaries approved routinely → UI:N. When meaningful review is required and performed, score UI:P or UI:A honestly — do not conflate trust exploitation with absent interaction.",
            True,
        ),
        # Phase 5 — BOD/SSVC
        (
            'Where CISA has published neither Automatable nor Technical Impact and the CVE is not in KEV, BOD 26-04 directs that they be treated as "no" and "total" respectively. SR/CVSS derivations apply only for non-CVE findings without Vulnrichment data.',
            "Where CISA has published neither Automatable nor Technical Impact and the CVE is not in KEV, CISA implementation guidance directs a 60-day timeline (FAQ missing-metadata rule). Do not table-lookup with default no/total when both are missing — that wrongly yields 14 days for publicly exposed assets. Automatable ≠ SR:R; Technical Impact ≠ VC:H alone. SR/CVSS derivations apply only as an explicitly labelled informative overlay for non-CVE findings.",
            True,
        ),
        (
            "Held as a lookup table, not boolean logic: the fast tier requires exposure or automatability in addition to KEV.",
            "Held as a lookup table, not boolean logic: for KEV-listed CVEs, the 3D/3DF tier requires exposure or automatability in addition to KEV; non-KEV rows can still reach 3D (e.g., exposed + automatable + total impact).",
            True,
        ),
        (
            "Since June 10, 2026, BOD 26-04 (CISA, 2026) has been the federal remediation standard for Federal Civilian Executive Branch agencies",
            "BOD 26-04 (CISA, 2026; effective June 10, 2026 for FCEB issuance) is the federal remediation standard for Federal Civilian Executive Branch agencies; FedRAMP NTC-0014 sets additional cloud milestones (Aug 7 / Dec 7 2026 / Mar 7 2027)",
            True,
        ),
        (
            "Severity does not determine remediation urgency. Since June 10, 2026, CISA has operationalized SSVC for federal remediation through BOD 26-04 (CISA, 2026)",
            "Severity does not determine remediation urgency. CISA operationalized SSVC for federal remediation through BOD 26-04 (CISA, 2026; FCEB effective June 10, 2026; FedRAMP timelines per NTC-0014)",
            True,
        ),
        (
            "The unmodified BOD result is always reported alongside the AIVSS recommendation; for FCEB agencies, BOD 26-04 is the compliance obligation.",
            "The baseline CISA SSVC/BOD table lookup is always reported separately from the optional AIVSS overlay; for FCEB agencies, the baseline `cisa:BOD2604:1.0.0` outcome is the compliance obligation.",
            True,
        ),
        (
            "3. Prior AIVSS integration was mathematically inert. Earlier drafts combined EPSS with a Threat Multiplier via `max(ThM_discrete, ThM_EPSS)` where `ThM_discrete(PoC) = 0.97` and `ThM_EPSS = 0.50 + 0.50 × EPSS`. Under `max()` selection, EPSS could change the result only when EPSS > 0.94 — a tiny fraction of the published distribution, most of which is already KEV-listed. Maximum achievable effect on severity: 0.3 points at the low end of the scale, and 0.1 points for findings above CVSS 7.0. The draft's own worked example showed EPSS 0.42 producing `ThM_EPSS = 0.71`, which was discarded. The integration appeared to use EPSS but did not.",
            "3. Prior AIVSS integration was mathematically inert — EPSS rarely changed outcomes under `max()` selection and appeared to use EPSS without material effect (Section 12.3.1 detail retained in reference implementation notes).",
            True,
        ),
        (
            "Consumer conformance. MUST parse all vector strings at its declared level; MUST NOT display an AIVSS score in a field that also carries CVSS scores without the `AIVSS:` prefix; MUST NOT substitute a missing Agentic AI metric group for an all-benign one.",
            CONFORMANCE_NOTE.strip(),
            True,
        ),
        (
            "Produce full reports with: `aivss-calc assess examples/asi06-example.json`",
            "Produce full reports with: `aivss-calc assess examples/asi06-example.json` (complete Mode 1 example: `examples/appendix-a-mode1-report.json`).",
            True,
        ),
    ]


def insert_after_anchor(anchor: str, text: str, label: str) -> None:
    doc = get_doc()
    rev = doc["revisionId"]
    idx = find_index(doc, anchor)
    batch_update(
        rev,
        [{"insertText": {"location": {"index": idx, "tabId": TAB_ID}, "text": text}}],
        label,
    )
    time.sleep(0.5)


def insert_appendix_example() -> None:
    if not APPENDIX_REPORT.exists():
        print(f"skip appendix: {APPENDIX_REPORT} missing")
        return
    doc = get_doc()
    body = ""
    tab = (doc.get("tabs") or [{}])[0]
    for el in ((tab.get("documentTab") or {}).get("body") or {}).get("content") or []:
        para = el.get("paragraph")
        if para:
            body += "".join(
                (pe.get("textRun") or {}).get("content", "")
                for pe in para.get("elements") or []
            )
    if '"finding_id": "AIVSS-ASI06-001"' in body and "appendix-a-mode1-report.json" in body:
        print("appendix example already present")
        return
    payload = json.dumps(
        json.loads(APPENDIX_REPORT.read_text(encoding="utf-8")),
        indent=2,
        sort_keys=False,
    )
    block = (
        "Complete Mode 1 report (schema-valid; examples/appendix-a-mode1-report.json):\n\n"
        f"{payload}\n\n"
    )
    anchor = "Validate structure against `schemas/aivss-report-v1.0.json`."
    chunk_size = 3200
    doc = get_doc()
    rev = doc["revisionId"]
    idx = find_index(doc, anchor)
    requests = []
    for i in range(0, len(block), chunk_size):
        chunk = block[i : i + chunk_size]
        requests.append(
            {"insertText": {"location": {"index": idx, "tabId": TAB_ID}, "text": chunk}}
        )
        idx += len(chunk)
    # one chunk expected; split if payload too large
    for n, req in enumerate(requests, 1):
        doc = get_doc()
        rev = doc["revisionId"]
        batch_update(rev, [req], f"appendix example part {n}")
        time.sleep(0.4)


def main() -> int:
    verify_account()
    reps = text_replacements()
    for n, (old, new, mc) in enumerate(reps, 1):
        if not old:
            continue
        doc = get_doc()
        rev = doc["revisionId"]
        try:
            batch_update(rev, [replace_all(old, new, mc)], f"phase25 replacement {n}")
        except RuntimeError as exc:
            if "No occurrences" in str(exc) or "not found" in str(exc).lower():
                print(f"skip {n}: not found")
            else:
                raise
        time.sleep(0.4)

    insert_after_anchor(
        "Table 4: MacroVector equivalence groups (EQ1–EQ6)",
        MACROVECTOR_EQ_TABLE,
        "insert MacroVector EQ table",
    )
    insert_after_anchor(
        "12.1 SSVC/BOD decision inputs",
        FAQ_60D_RULE,
        "insert 60D FAQ rule",
    )
    insert_after_anchor(
        "12.4 Agentic AI Effect Class escalation",
        FEDRAMP_MILESTONES,
        "insert FedRAMP milestones",
    )
    insert_after_anchor(
        "8 End-to-End Assessment Flow",
        PIPELINE_ORDER,
        "insert pipeline order",
    )
    insert_appendix_example()

    # Refresh inventory
    subprocess.run(
        [sys.executable, str(REPO / "scripts" / "fetch_and_inventory_doc.py")],
        check=True,
    )
    print("phase 2-5 remediation complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
