#!/usr/bin/env python3
"""Apply AIVSS v1 production remediation Phases 6-8 + FedRAMP date gap."""
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
    find_index,
    get_doc,
    replace_all,
    verify_account,
)

PRESERVE = r"C:\Users\kenhu\.claude\skills\gws-google-doc-review\scripts\preserve_comment_span.py"
CALC_SHA = subprocess.check_output(
    ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
).strip()
CALC_BRANCH = "remove-mode2-candidate-adjusted"
PYTEST_COUNT = "127"

FEDRAMP_NTC = "https://www.fedramp.gov/notices/0014/"
CISA_BOD = (
    "https://www.cisa.gov/news-events/directives/"
    "bod-26-04-prioritizing-security-updates-based-risk"
)
APOLLO_URL = "https://www.apolloresearch.ai/research/claude-sonnet-3-7-evaluation-awareness"
NGUYEN_URL = "https://arxiv.org/abs/2507.01786"
NIST_800_53 = "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"

ASSESSOR_SUMMARY = (
    "Assessor quick start. To score a finding: (1) classify under ASI01–ASI10; "
    "(2) build an honest cvss_vector with agent-specific interpretation (Section 9) "
    "and set Exploit Maturity (E) from the evidence ladder before interpolating "
    "severity; (3) record a complete eight-metric aivss_vector or omit the profile; "
    "(4) run the reference calculator for Mode 1 AIVSS = CVSS-BTE and the Agentic "
    "AI Effect Class; (5) at Level 2, resolve the SSVC/BOD decision track "
    "separately. Synthetic reference fixtures in `examples/` illustrate each ASI "
    "category; they are not field measurements.\n"
)

FEDRAMP_EXEC_OLD = (
    "FedRAMP NTC-0014 sets additional cloud milestones (Aug 7 / Dec 7 2026 / Mar 7 2027)"
)
FEDRAMP_EXEC_NEW = (
    "FedRAMP NTC-0014 (https://www.fedramp.gov/notices/0014/) sets cloud policy "
    "milestones distinct from FCEB BOD issuance (June 10, 2026; "
    "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk): "
    "agency policies by August 7, 2026; begin BOD remediation timelines December 7, 2026 "
    "for FedRAMP-authorized systems; CSP grace through March 7, 2027"
)

FEDRAMP_BLOCK_OLD = (
    "FedRAMP policy milestones (NTC-0014, Aug 7 2026): CSPs must align with BOD "
    "26-04 by Aug 7 2026; BOD remediation timelines begin Dec 7 2026 for "
    "FedRAMP-authorized systems; CSP grace period ends Mar 7 2027. June 10 2026 "
    "is the BOD issuance date for FCEB agencies, not the sole deadline regime for "
    "all federal cloud workloads."
)
FEDRAMP_BLOCK_NEW = (
    "FedRAMP / BOD milestone split (informative). BOD 26-04 issuance / FCEB "
    "obligation: June 10, 2026 (https://www.cisa.gov/news-events/directives/"
    "bod-26-04-prioritizing-security-updates-based-risk). FedRAMP NTC-0014 "
    "(https://www.fedramp.gov/notices/0014/): CSPs must align agency policies "
    "with BOD 26-04 by August 7, 2026; begin BOD remediation timelines "
    "December 7, 2026 for FedRAMP-authorized systems; CSP grace period through "
    "March 7, 2027. June 10, 2026 is BOD issuance for FCEB agencies, not the "
    "sole deadline regime for all federal cloud workloads."
)

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
    "Qualitative → numeric mapping (organization-local, publish internally): "
    "Criticality {Low→1, Medium→2, High→3}; Reach {Single→1, Department→2, "
    "Enterprise→3}; Likelihood uses NIST SP 800-30 Rev. 1 ordinal bands mapped to "
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

LINK_TARGETS = (
    (FEDRAMP_NTC, FEDRAMP_NTC),
    (CISA_BOD, CISA_BOD),
    (APOLLO_URL, APOLLO_URL),
    (NGUYEN_URL, NGUYEN_URL),
    (NIST_800_53, NIST_800_53),
    ("https://www.first.org/cvss/v4.0/specification-document", "https://www.first.org/cvss/v4.0/specification-document"),
)


def apply_replacement(old: str, new: str, label: str) -> None:
    if not old or old == new:
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


def preserve_replace(old: str, new: str, label: str) -> None:
    if old == new:
        return
    proc = subprocess.run(
        [
            sys.executable,
            PRESERVE,
            "--doc",
            DOC_ID,
            "--old",
            old,
            "--new",
            new,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        print(f"preserve_replace failed {label}: {proc.stderr or proc.stdout[-1500:]}")
        apply_replacement(old, new, label)
    else:
        print(f"preserve {label}")
    time.sleep(0.35)


def insert_after(anchor: str, text: str, label: str) -> None:
    doc = get_doc()
    rev = doc["revisionId"]
    idx = find_index(doc, anchor)
    batch_update(
        rev,
        [{"insertText": {"location": {"index": idx, "tabId": TAB_ID}, "text": text}}],
        label,
    )
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


def fix_misstyled_definition_headings() -> None:
    doc = get_doc()
    requests: list[dict] = []
    for start, end, text, style in iter_paragraphs(doc):
        stripped = text.strip()
        if style == "HEADING_3" and stripped.startswith("Definition."):
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
        print("no mis-styled Definition headings")
        return
    doc = get_doc()
    rev = doc["revisionId"]
    batch_update(rev, requests[:8], "fix Definition headings")
    time.sleep(0.35)


def apply_hyperlinks() -> None:
    doc = get_doc()
    requests: list[dict] = []
    for start, _end, text, _style in iter_paragraphs(doc):
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
        print("no hyperlink targets")
        return
    for i in range(0, len(requests), 10):
        doc = get_doc()
        rev = doc["revisionId"]
        batch_update(rev, requests[i : i + 10], f"hyperlinks {i // 10 + 1}")
        time.sleep(0.35)


def text_replacements() -> list[tuple[str, str, str]]:
    """(old, new, label) — use preserve for long unique spans when needed."""
    apollo_trace = (
        'Apollo Research has documented growing "evaluation awareness" in frontier reasoning models, '
        "and reports that while today's models are unlikely to be using this awareness to hide "
        "misalignment, they are becoming rapidly more situationally aware and strategic in ways that "
        "would make such concealment possible. Recent white-box interpretability work has further "
        "observed that this awareness is beginning to shift from verbalized chain-of-thought reasoning "
        "toward forms that leave no trace in visible reasoning at all"
    )
    apollo_precise = (
        "Apollo Research (2025-03-17) reported evaluation-awareness behaviours in Claude Sonnet 3.7 "
        f"({APOLLO_URL}); Nguyen et al. (arXiv:2507.01786v2) document white-box evidence of "
        f"latent reasoning not reflected in visible chain-of-thought ({NGUYEN_URL}). These are "
        "reconstructable external records cited for traceability risk context; they do not prove "
        "deployment-level untraceability in every agent system"
    )
    return [
        (FEDRAMP_EXEC_OLD, FEDRAMP_EXEC_NEW, "FedRAMP exec dates"),
        (FEDRAMP_BLOCK_OLD, FEDRAMP_BLOCK_NEW, "FedRAMP milestone block"),
        (
            "Table 8 crosswalks each retired AIVSS Agentic AI Core Risk category to its OWASP ASI successor (or to TD for Agent Untraceability), preserving lineage from the OWASP AIVSS project research.",
            "Table 8 is a conceptual many-to-many crosswalk — not a claim of direct one-to-one descent. Each retired AIVSS core risk may inform multiple OWASP ASI categories (or TD for Agent Untraceability); OWASP ASI09 and ASI10 have no retired AIVSS predecessor. The table preserves research lineage from the OWASP AIVSS project team.",
            "Table 8 ancestry",
        ),
        (
            "Eight of ten OWASP ASI categories trace their research lineage directly to the original AIVSS core risk taxonomy (see crosswalk in Section 5.5).",
            "Eight of ten OWASP ASI categories share research lineage with themes from the original AIVSS core risk taxonomy (see many-to-many crosswalk in Section 5.5); this is affiliation and thematic continuity, not OWASP endorsement or one-to-one supersession of v0.8.",
            "lineage direct descent",
        ),
        (
            "2. Agent Untraceability ranked third — contributors rated opaque agent behaviour as nearly as consequential as direct exploitation, because it prevents scoping, attribution, and safe rollback. This validated retaining it in AIVSS 1.0 as mandatory TD assessment even without an OWASP ASI category.",
            "2. In the v0.8 contributor survey (Appendix D; illustrative, n≈30), Agent Untraceability received a high median impact score (third among ten themes) — contributors rated opaque agent behaviour as nearly as consequential as direct exploitation for scoping and rollback. This informed retaining mandatory TD assessment; it is not an OWASP Top 10 rank claim.",
            "Untraceability rank",
        ),
        (
            "Methodology (summary). Contributors ranked risk themes on a 1–10 impact scale and indicated prevalence in production agent deployments. Results were aggregated by median rank. This appendix preserves the relative ordering that shaped AIVSS research; it is informative, not a scoring input.",
            "Methodology (summary). Contributors ranked risk themes on a 1–10 impact scale and indicated prevalence in production agent deployments. Results were aggregated by median impact score (non-integer medians are expected on a 1–10 scale). Table 27 is illustrative and reconciled with v0.8 survey records where available; it is informative, not a scoring input.",
            "survey methodology",
        ),
        (
            "Table 27 ranks the original ten AIVSS Agentic AI Core Risks by median contributor impact score and shows how each was adopted into OWASP ASI or retained as the TD metric in version 1.0.",
            "Table 27 (illustrative) ranks the original ten AIVSS Agentic AI Core Risks by median contributor impact score from the v0.8-era survey and shows how each theme maps to OWASP ASI or TD in version 1.0.",
            "Table 27 illustrative",
        ),
        (
            "MAESTRO's threat taxonomy uses ASI threat IDs (T1–T15) and cross-layer analysis; practitioners map validated threats to OWASP ASI01–ASI10 for AIVSS classification.",
            "MAESTRO's seven architecture layers (Foundation Models through Agent Ecosystem) are distinct from OWASP detailed taxonomy IDs T1–T15; practitioners map MAESTRO-layer threats to OWASP ASI01–ASI10 for AIVSS classification after validation.",
            "MAESTRO layers",
        ),
        (
            "Table 24 explains how AIVSS outputs integrate with NIST RMF, NIST AI RMF, CSA MAESTRO Agentic AI threat modeling, CERT/CC SSVC and CISA BOD 26-04, ISO 27001, CVSS/FIRST, and MITRE ATLAS without claiming endorsement or replacing those frameworks.",
            "Table 24 explains how AIVSS outputs integrate with NIST RMF (RA-3 risk assessment using NIST SP 800-53 control catalog as security control baseline), NIST AI RMF, CSA MAESTRO Agentic AI threat modeling, CERT/CC SSVC and CISA BOD 26-04, ISO 27001, CVSS/FIRST, and MITRE ATLAS. AIVSS is affiliated with v0.8 research lineage; it is not OWASP-approved and does not supersede v0.8 publications — it retires v0.8 normative scoring while preserving taxonomy credit.",
            "RMF RA-3",
        ),
        (
            "5. Continued expert review of assurance-metric rubrics (EX, PT, CA, TD) and inter-rater reliability (Section 17).",
            "5. Continued expert review of assurance-metric rubrics (EX, PT, CA, TD) and inter-rater reliability studies.",
            "section 17 self-ref",
        ),
        (
            "Figure 2 walks through the end-to-end assessment path — from separate cvss_vector and aivss_vector inputs through Mode 1 AIVSS scoring and parallel SSVC/BOD remediation timeline resolution (Layer 3) — showing where each output is produced.",
            "Figure 2 walks through the end-to-end assessment path — Exploit Maturity (E) is resolved on cvss_vector before CVSS-BTE / Mode 1 severity interpolation; aivss_vector is scored in parallel; SSVC/BOD Layer 3 runs on its own inputs. No Mode 2 extended severity path.",
            "Figure 2 caption",
        ),
        (
            "Figure 2: Assessment flow (with SSVC/BOD Layer 3 decision track)",
            "Figure 2: Assessment flow — E before severity; parallel Agentic AI Profile; SSVC/BOD Layer 3 (no Mode 2)",
            "Figure 2 title",
        ),
        (
            "Table 19 presents reference-calculator outputs for one worked example per ASI01–ASI10 category — showing AIVSS severity, Agentic AI Effect Class, and both BOD and AIVSS-recommended remediation timelines.",
            "Table 19 presents synthetic reference-calculator fixtures — one per ASI01–ASI10 — showing Mode 1 AIVSS severity only, Agentic AI Effect Class, and BOD / AIVSS-recommended remediation timelines.",
            "Table 19 synthetic",
        ),
        (
            "Finding narrative. ASI06 Memory and Context Poisoning. Adversarial content is planted in the agent's shared context store, reaches a tool-invocation path directly, propagates to sibling agents, and reproduces reliably. No reasoning trace is retained.",
            "Finding narrative (synthetic fixture). ASI06 Memory and Context Poisoning. Adversarial content is planted in the agent's shared context store, reaches a tool-invocation path directly, propagates to sibling agents, and reproduces reliably. No reasoning trace is retained. Mode 1 AIVSS = CVSS-BTE 7.8; no extended severity path.",
            "ASI06 narrative",
        ),
        (
            "The AIVSS-P row uses `examples/asi06-memory-poisoning.json` (likelihood 0.72):",
            "Optional AIVSS-P example uses `examples/asi06-example.json` with `include_priority: true` and likelihood 0.72 (organization-local fixture):",
            "ASI06 AIVSS-P path",
        ),
        (
            "Band cut-points (p90 / p65 / p35 of a uniform grid, n = 10,980, severity 4.0–10.0): Immediate ≥ 78, This sprint ≥ 64, Scheduled ≥ 53, Backlog below 53. The grid over-represents high-severity findings relative to a real portfolio; organizations SHOULD recalibrate cut-points against their own assessment corpus (Section 22).",
            "Band cut-points are provisional: p90 / p65 / p35 of an artificial uniform grid (n = 10,980, severity 4.0–10.0) yield Immediate ≥ 78, This sprint ≥ 64, Scheduled ≥ 53, Backlog < 53. This grid over-represents high-severity findings; organizations MUST recalibrate cut-points against their own corpus (Section 22) before using bands for release decisions.",
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
            "Table 23 TD",
        ),
        (
            f"Normative pin: branch {CALC_BRANCH}, commit 238309c1048926443cc339503049e639bcf23fc6.",
            f"Normative pin: branch {CALC_BRANCH}, commit {CALC_SHA}.",
            "ref impl pin",
        ),
        ("# 93 tests", f"# {PYTEST_COUNT} pytest", "93 tests code block"),
        (apollo_trace, apollo_precise, "traceability citations"),
    ]


def add_references() -> None:
    doc = get_doc()
    body = ""
    for _s, _e, text, _st in iter_paragraphs(doc):
        body += text
    refs = [
        (
            "(Householder et al., 2019). SSVC: Stakeholder-Specific Vulnerability Categorization.",
            f"(Apollo Research, 2025). Claude Sonnet 3.7 Evaluation Awareness (2025-03-17). {APOLLO_URL}\n",
        ),
    ]
    if "Apollo Research, 2025" in body:
        print("Apollo reference already present")
    else:
        anchor = "(Householder et al., 2019). SSVC: Stakeholder-Specific Vulnerability Categorization."
        insert_after(anchor + "\n", refs[0][1], "insert Apollo ref")
    if "Nguyen" in body and "2507.01786" in body:
        print("Nguyen reference already present")
    else:
        anchor = f"(Apollo Research, 2025). Claude Sonnet 3.7 Evaluation Awareness (2025-03-17). {APOLLO_URL}"
        nguyen = (
            f"(Nguyen et al., 2025). Latent reasoning traces in language models. arXiv:2507.01786v2. {NGUYEN_URL}\n"
        )
        try:
            insert_after(anchor, "\n" + nguyen, "insert Nguyen ref")
        except KeyError:
            insert_after(
                "(NIST, 2012). SP 800-30 Rev. 1",
                nguyen,
                "insert Nguyen ref fallback",
            )
    if "SP 800-53" in body:
        print("NIST 800-53 reference already present")
    else:
        nist53 = (
            f"(NIST, 2020). SP 800-53 Rev. 5 — Security and Privacy Controls. {NIST_800_53}\n"
        )
        insert_after(
            "(NIST, 2012). SP 800-30 Rev. 1",
            "\n" + nist53,
            "insert NIST 800-53 ref",
        )


def main() -> int:
    verify_account()

    insert_after(
        "deployed software that can plan, use tools, retain context, and act with some autonomy.",
        "\n" + ASSESSOR_SUMMARY,
        "assessor-first summary",
    )

    for old, new, label in text_replacements():
        if label.startswith("FedRAMP") or label in ("traceability citations",):
            preserve_replace(old, new, label)
        else:
            apply_replacement(old, new, label)

    insert_after(
        "Each quantity is priced exactly once. Exploitation evidence belongs to the decision track (Section 12), not AIVSS-P.",
        "\n" + AIVSS_P_RULES,
        "AIVSS-P rules",
    )
    insert_after(
        "Table 23: Recommended Release Gates",
        "\n" + RELEASE_GATES,
        "release gate rules",
    )
    insert_after(
        "Input vector:",
        "\n" + ASI06_METRIC_RATIONALE,
        "ASI06 metric rationale",
    )

    fix_misstyled_definition_headings()
    add_references()
    apply_hyperlinks()

    subprocess.run(
        [sys.executable, PRESERVE, "--doc", DOC_ID, "--check"],
        check=False,
    )
    subprocess.run(
        [sys.executable, str(REPO / "scripts" / "final_scan_counts.py")],
        check=True,
    )
    print("phase 6-8 remediation complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
