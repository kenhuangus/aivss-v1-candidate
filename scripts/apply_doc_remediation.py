#!/usr/bin/env python3
"""Apply Phase 1 + Phase 2 start remediation to AIVSS v1 Google Doc."""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DOC_ID = "1SIO6yN1x4XXTnclLeEsFFHnqzRR-3SOvUJTHF7CGRpI"
HELPER = r"C:\Users\kenhu\.claude\skills\gws-google-doc-review\scripts\gws_profile.py"
TAB_ID = "t.0"
CALC_SHA = "238309c1048926443cc339503049e639bcf23fc6"
CALC_BRANCH = "remove-mode2-candidate-adjusted"

WITHDRAWAL_NOTE = (
    "Withdrawn from AIVSS 1.0 normative scope. Mode 2 MacroVector equivalence-class "
    "promotion (formerly AIVSS-BTEA / experimental MacroVector) and additive severity "
    "uplift from assurance metrics (EX+PT+CA+TD, formerly candidate_adjusted) are "
    "removed from this 1.0 specification. Normative severity is Mode 1 only: "
    "AIVSS = CVSS-BTE. The eight-metric Agentic AI Profile (LC, CP, AP, SR, EX, PT, "
    "CA, TD) and Agentic AI Effect Class (A0/A1/A2) are parallel metadata; they do not "
    "modify the published severity number.\n"
)

VECTOR_SYNTAX_BLOCK = (
    "CVSS and AIVSS vectors are separate strings following the CVSS v4.0 Extensions "
    "Framework (FIRST, 2024). Do not append AIVSS metrics to a CVSS:4.0 vector or "
    "describe the combined form as a standard CVSS vector.\n\n"
    "cvss_vector (required for Level 1):\n"
    "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P\n\n"
    "aivss_vector (required for Level 1 when agentic context applies):\n"
    "AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H\n\n"
    "Metric order is fixed: LC / CP / AP / SR / EX / PT / CA / TD. "
    "LC–SR classify the Agentic AI Effect Class (Section 11). "
    "EX, PT, CA, and TD record assurance deficits as parallel metadata; "
    "they do not modify the Mode 1 severity number.\n"
)

EIGHT_METRIC_SUBSECTIONS = (
    "10.5 EX — Extension Surface\n"
    "Definition. Breadth of attacker-reachable extensions (tools, plugins, MCP servers, "
    "code execution) on this exploit path.\n"
    "Table 15a defines EX levels (Wide, Medium, Narrow, None). EX is recorded in every "
    "conformant assessment and does not modify the Mode 1 severity number.\n\n"
    "10.6 PT — Provider Trust Deficit\n"
    "Definition. Degree to which the deployment depends on unaudited or unverified "
    "third-party model, tool, or orchestration providers on this path.\n"
    "Table 15b defines PT levels (High, Medium, Low, None). PT does not modify the "
    "Mode 1 severity number.\n\n"
    "10.7 CA — Cost Abuse Surface\n"
    "Definition. Attacker ability to trigger unbounded or disproportionate compute, "
    "token, or API cost on this path.\n"
    "Table 15c defines CA levels (Wide, Medium, None). CA does not modify the Mode 1 "
    "severity number.\n\n"
)

REF_IMPL_BODY = (
    "Reference calculator: https://github.com/kenhuangus/aivss-v1-candidate\n"
    f"Normative pin: branch {CALC_BRANCH}, commit {CALC_SHA}.\n"
    "Install with pip install -e package dev extras; run aivss-calc verify and pytest.\n"
    "Example: aivss-calc assess examples/asi06-example.json\n"
)


def gws(*args: str) -> dict:
    proc = subprocess.run(
        [sys.executable, HELPER, "run", "--", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout[-4000:])
    text = proc.stdout
    start = text.find("{")
    if start < 0:
        start = text.find("[")
    if start < 0:
        raise RuntimeError(f"no JSON:\n{text[:2000]}")
    return json.loads(text[start:])


def verify_account() -> None:
    about = gws("drive", "about", "get", "--params", json.dumps({"fields": "user(emailAddress)"}))
    email = (about.get("user") or {}).get("emailAddress")
    if email != "kenhuangus@gmail.com":
        raise SystemExit(f"wrong account: {email}")
    print(f"verified {email}")


def get_doc() -> dict:
    return gws(
        "docs",
        "documents",
        "get",
        "--params",
        json.dumps({"documentId": DOC_ID, "includeTabsContent": True}),
    )


import urllib.error
import urllib.request


def batch_update(revision_id: str, requests: list[dict], label: str) -> None:
    payload = {"requests": requests, "writeControl": {"requiredRevisionId": revision_id}}
    raw = json.dumps(payload)
    if len(raw) > 7000:
        raise RuntimeError(f"payload too long ({len(raw)} bytes) for {label}")
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
            raw,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout[-4000:])
    print(f"applied {label}: {len(requests)} requests ({len(raw)} bytes)")


def replace_all(old: str, new: str, match_case: bool = True) -> dict:
    return {
        "replaceAllText": {
            "containsText": {"text": old, "matchCase": match_case},
            "replaceText": new,
        }
    }


def find_index(doc: dict, needle: str) -> int:
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
        if needle in text:
            return el["startIndex"]
    raise KeyError(f"needle not found: {needle!r}")


def find_range(doc: dict, start_needle: str, end_needle: str) -> tuple[int, int]:
    tab = (doc.get("tabs") or [{}])[0]
    start = end = None
    for el in ((tab.get("documentTab") or {}).get("body") or {}).get("content") or []:
        para = el.get("paragraph")
        if not para:
            continue
        text = ""
        for pe in para.get("elements") or []:
            tr = pe.get("textRun")
            if tr:
                text += tr.get("content", "")
        if start is None and text.strip().startswith(start_needle):
            start = el["startIndex"]
        if start is not None and text.strip().startswith(end_needle):
            end = el["startIndex"]
            break
    if start is None or end is None:
        raise KeyError(f"range not found: {start_needle!r} .. {end_needle!r}")
    return start, end


def text_replacements() -> list[tuple[str, str, bool]]:
    """(old, new, match_case)"""
    return [
        # Executive Summary / architecture — remove Mode 2 normative claims
        (
            "Agentic properties are instead recorded in a parallel five-metric Agentic AI Profile (LC, CP, AP, SR, TA) that does not modify the numeric severity score (Section 2.3, Section 9, Section 10). A provisional Mode 2 replaces the old ten-factor multiplier with MacroVector-class promotion drawn from FIRST's own lookup table (Section 13.2).",
            "Agentic properties are instead recorded in a parallel eight-metric Agentic AI Profile (LC, CP, AP, SR, EX, PT, CA, TD) that does not modify the numeric severity score (Section 2.3, Section 9, Section 10).",
            True,
        ),
        (
            "integrate extensions via lookup tables — MacroVector for Mode 2 severity and the CISA SSVC deployer decision table for Layer 3 — not arithmetic",
            "integrate extensions via lookup tables — the CISA SSVC deployer decision table for Layer 3 remediation — not arithmetic severity uplift",
            True,
        ),
        (
            "A structured extension to the CVSS vector string consisting of five named dimensions — LC (Language-Mediated Control), CP (Context Persistence), AP (Agentic Propagation), SR (Stochastic Exploit Reliability), and TA (Traceability Avoidance / Agent Untraceability) — that describe agent-specific properties not already captured by CVSS Base metrics.",
            "An eight-metric extension profile — LC (Language-Mediated Control), CP (Context Persistence), AP (Agentic Propagation), SR (Stochastic Exploit Reliability), EX (Extension Surface), PT (Provider Trust Deficit), CA (Cost Abuse Surface), and TD (Traceability Deficit) — recorded in a separate aivss_vector string. It describes agent-specific properties not already captured by CVSS Base metrics and does not modify the CVSS vector.",
            True,
        ),
        (
            "The Agentic AI Profile records residual agentic properties after everything mappable into CVSS has been scored there (Section 2.3, Section 9). TA is always assessed because OWASP Top 10 has no ASI category for Agent Untraceability (Section 5.6). The Agentic AI Profile does not modify the Mode 1 severity number; it provides parallel metadata for prioritization, forensic response, remediation escalation, and optional extended scoring.",
            "The Agentic AI Profile records residual agentic properties after everything mappable into CVSS has been scored there (Section 2.3, Section 9). TD is always assessed because OWASP Top 10 has no ASI category for Agent Untraceability (Section 5.6). The Agentic AI Profile does not modify the Mode 1 severity number; it provides parallel metadata for prioritization, forensic response, and remediation escalation.",
            True,
        ),
        (
            "The class affects SSVC remediation outcome escalation (Section 12.4) and optional Mode 2 scoring (Section 13.2); it does not change the Mode 1 severity number.",
            "The class affects SSVC remediation outcome escalation (Section 12.4); it does not change the Mode 1 severity number.",
            True,
        ),
        (
            "map everything possible into CVSS; score only the AI-specific residual as named metrics (LC, CP, AP, SR, TA); integrate any extension through lookup tables (MacroVector for Mode 2; SSVC decision tables for Layer 3), not arithmetic uplift. This means the primary severity number is always a score that exists within the CVSS measurement model — AIVSS never invents a number the CVSS SIG's process did not produce. Agentic properties already representable in CVSS (tool reach → SC/SI/SA; agent credential → PR; autonomous execution → UI:N) must be scored in CVSS, not duplicated in the Agentic AI Profile (Section 9.3). Mode 2 uses MacroVector promotion from FIRST's lookup table (Section 13.2); Layer 3 uses the CISA SSVC deployer decision table (Section 12.0). Neither Mode 2 nor Layer 3 extensions are suitable substitutes for BOD compliance gates.",
            "map everything possible into CVSS; score only the AI-specific residual as named metrics (LC, CP, AP, SR, EX, PT, CA, TD); integrate remediation timing through lookup tables (SSVC decision tables for Layer 3), not arithmetic severity uplift. This means the primary severity number is always a score that exists within the CVSS measurement model — AIVSS never invents a number the CVSS SIG's process did not produce. Agentic properties already representable in CVSS (tool reach → SC/SI/SA; agent credential → PR; autonomous execution → UI:N) must be scored in CVSS, not duplicated in the Agentic AI Profile (Section 9.3). Layer 3 uses the CISA SSVC deployer decision table (Section 12.0). Layer 3 outputs are not substitutes for BOD compliance gates.",
            True,
        ),
        (
            "Table 4 groups CVSS Base metrics into the six equivalence classes (EQ1–EQ6) that define MacroVector identity in CVSS v4.0 and underpin Mode 2 promotion in Section 13.2.",
            "Table 4 groups CVSS Base metrics into the six equivalence classes (EQ1–EQ6) that define MacroVector identity in CVSS v4.0.",
            True,
        ),
        (
            "Agentic AI metric group. The five-metric vector extension (LC / CP / AP / SR / TA) that forms the core of the Agentic AI Profile (Section 10).",
            "Agentic AI metric group. The eight-metric vector extension (LC / CP / AP / SR / EX / PT / CA / TD) that forms the core of the Agentic AI Profile (Section 10), carried in a separate aivss_vector string.",
            True,
        ),
        (
            "Agentic AI Effect Class (A). A boolean classification A0, A1, or A2 derived from the Agentic AI metric group (Section 11). It affects remediation escalation and optional Mode 2 scoring; it does not change the Mode 1 severity number.",
            "Agentic AI Effect Class (A). A boolean classification A0, A1, or A2 derived from classifying metrics LC, CP, AP, and SR (Section 11). It affects remediation escalation; it does not change the Mode 1 severity number.",
            True,
        ),
        (
            "Mode 2 (provisional). `AIVSS-BTEA = Lookup_AIVSS(EQ1..EQ6, A)` — a MacroVector promotion lookup (Section 13.2). Provisional pending expert calibration; not for compliance gates.\n",
            "",
            True,
        ),
        (
            "The Agentic AI Effect Class is a boolean ladder; Mode 2 is a table lookup. Ordinal factors must not be averaged or multiplied into a severity formula (Williams, 2025).",
            "The Agentic AI Effect Class is a boolean ladder. Ordinal factors must not be averaged or multiplied into a severity formula (Williams, 2025).",
            True,
        ),
        (
            "Figure 1 maps the AIVSS 1.0 architecture: Layer 1 computes honest CVSS-BTE severity, Layer 2 records the Agentic AI Profile and Agentic AI Effect Class, and Layer 3 applies the CISA SSVC/BOD 26-04 decision-table model (Section 12.0) with optional Mode 2 extended severity and internal AIVSS-P priority.",
            "Figure 1 maps the AIVSS 1.0 architecture: Layer 1 computes honest CVSS-BTE severity, Layer 2 records the Agentic AI Profile and Agentic AI Effect Class, and Layer 3 applies the CISA SSVC/BOD 26-04 decision-table model (Section 12.0) with optional internal AIVSS-P priority.",
            True,
        ),
        (
            "Optional Mode 2 (Section 13.2). MacroVector promotion for extended severity — provisional.\n",
            "",
            True,
        ),
        (
            "Layer 2 — Agentic AI Profile (Section 10). Five dimensions describing language-mediated control, context persistence, agentic propagation, stochastic exploit reliability, and traceability avoidance. Output: vector extension and Agentic AI Effect Class (Section 11).",
            "Layer 2 — Agentic AI Profile (Section 10). Eight dimensions: LC, CP, AP, SR (classifying) and EX, PT, CA, TD (assurance metadata). Output: separate aivss_vector and Agentic AI Effect Class (Section 11).",
            True,
        ),
        (
            "The ten historical AIVSS amplification factors resolve into either CVSS Base metrics or the five Agentic AI metrics:",
            "The ten historical AIVSS amplification factors resolve into either CVSS Base metrics or the eight Agentic AI metrics:",
            True,
        ),
        (
            "Table 9 shows how each historical agentic amplification factor is scored — wholly in CVSS, wholly as an AI metric (LC/CP/AP/SR/TA), or split — so assessors do not double-count the same property.",
            "Table 9 shows how each historical agentic amplification factor is scored — wholly in CVSS, wholly as an AI metric (LC/CP/AP/SR/EX/PT/CA/TD), or split — so assessors do not double-count the same property.",
            True,
        ),
        (
            "- MUST supply all four scored Agentic AI metrics (LC, CP, AP, SR), or explicitly none.\n- MUST assess TA (Agent Untraceability) for every finding — record TA:H, TA:M, or TA:L in the Agentic AI Profile (Section 5.6, Section 10.5). TA does not modify the severity number but is a required risk-factor consideration.",
            "- MUST supply cvss_vector and aivss_vector as separate strings (Section 10.9), or explicitly omit the Agentic AI Profile.\n- MUST supply all eight Agentic AI metrics (LC, CP, AP, SR, EX, PT, CA, TD) when the profile is present.\n- MUST assess TD (Traceability Deficit / Agent Untraceability) for every finding — record TD:H, TD:M, or TD:L (Section 5.6, Section 10.8). TD does not modify the severity number but is a required risk-factor consideration.",
            True,
        ),
        (
            "Figure 2 walks through the end-to-end assessment path — from CVSS vector and optional Agentic AI Profile through Mode 1 AIVSS scoring, parallel SSVC/BOD remediation timeline resolution (Layer 3), and optional Mode 2 BTEA lookup — showing where each output is produced.",
            "Figure 2 walks through the end-to-end assessment path — from separate cvss_vector and aivss_vector inputs through Mode 1 AIVSS scoring and parallel SSVC/BOD remediation timeline resolution (Layer 3) — showing where each output is produced.",
            True,
        ),
        (
            "4. Run the calculator to obtain AIVSS severity (Mode 1), Agentic AI Effect Class, and optionally Mode 2 extended severity.",
            "4. Run the calculator to obtain AIVSS severity (Mode 1) and Agentic AI Effect Class.",
            True,
        ),
        (
            "When Agentic AI metrics are present, they are parsed as an optional extension group in fixed order: LC / CP / AP / SR / TA. The tool computes an interpolated CVSS-BTE score, classifies the Agentic AI Effect Class, and emits Mode 1 (normative) and optionally Mode 2 (provisional) scores. At Level 2, the SSVC decision-table track (`cisa:DT_BOD2604:1.0.0`) runs in parallel with severity scoring.",
            "When Agentic AI metrics are present, they are parsed from aivss_vector in fixed order: LC / CP / AP / SR / EX / PT / CA / TD. The tool computes an interpolated CVSS-BTE score from cvss_vector alone, classifies the Agentic AI Effect Class from LC–SR, and emits the Mode 1 (normative) AIVSS score. At Level 2, the SSVC decision-table track (`cisa:DT_BOD2604:1.0.0`) runs in parallel with severity scoring.",
            True,
        ),
        (
            "3. Add the Agentic AI metric group (LC, CP, AP, SR, and TA for Agent Untraceability) per Section 10.",
            "3. Add the Agentic AI metric group (LC, CP, AP, SR, EX, PT, CA, TD) in a separate aivss_vector per Section 10.",
            True,
        ),
        (
            "The Agentic AI metric group captures agent-specific properties that CVSS Base metrics do not separately name. Scored metrics: LC, CP, AP, SR. Mandatory non-scoring metric: TA (Agent Untraceability; Section 5.6, Section 7).",
            "The Agentic AI metric group captures agent-specific properties that CVSS Base metrics do not separately name. Classifying metrics (LC, CP, AP, SR) determine the Agentic AI Effect Class. Assurance metrics (EX, PT, CA, TD) are recorded as parallel metadata; TD implements Agent Untraceability (Section 5.6, Section 7). None modify the Mode 1 severity number.",
            True,
        ),
        (
            "All four scored metrics MUST be present together or all absent. TA is required in every conformant assessment (Section 7). An unknown key MUST cause a parse failure.",
            "All eight metrics MUST be present together in aivss_vector or the profile omitted entirely. TD is required in every conformant assessment (Section 7). An unknown key MUST cause a parse failure.",
            True,
        ),
        (
            "10.5 TA — Traceability Avoidance (Agent Untraceability)",
            "10.8 TD — Traceability Deficit (Agent Untraceability)",
            True,
        ),
        (
            "Definition — TA (Traceability Avoidance). The degree to which post-incident reconstruction of an agent's reasoning, prompts, and tool actions is infeasible. High traceability avoidance means the deployment exhibits Agent Untraceability: defenders cannot reliably determine what the agent did, why, or on whose behalf.",
            "Definition — TD (Traceability Deficit). The degree to which post-incident reconstruction of an agent's reasoning, prompts, and tool actions is infeasible. High traceability deficit means the deployment exhibits Agent Untraceability: defenders cannot reliably determine what the agent did, why, or on whose behalf.",
            True,
        ),
        (
            "Scoring rule. TA is recorded in every conformant assessment. TA never affects the Mode 1 severity number (AIVSS = CVSS-BTE). It informs response priority, forensic procedures, control requirements, and release gating. When TA:H, assessors SHOULD treat scope of compromise as unknown until proven otherwise.",
            "Scoring rule. TD is recorded in every conformant assessment. TD never affects the Mode 1 severity number (AIVSS = CVSS-BTE). It informs response priority, forensic procedures, control requirements, and release gating. When TD:H, assessors SHOULD treat scope of compromise as unknown until proven otherwise.",
            True,
        ),
        (
            "Table 14 defines the TA metric levels (High, Medium, Low) for Agent Untraceability — a mandatory AIVSS risk factor retained from the original OWASP AIVSS taxonomy that does not change the Mode 1 severity number.",
            "Table 14 defines the TD metric levels (High, Medium, Low) for Agent Untraceability — a mandatory AIVSS risk factor retained from the original OWASP AIVSS taxonomy that does not change the Mode 1 severity number.",
            True,
        ),
        (
            "Table 14: TA — Traceability Avoidance (Agent Untraceability)",
            "Table 14: TD — Traceability Deficit (Agent Untraceability)",
            True,
        ),
        (
            "Assessment guidance. Evaluate TA from deployment architecture, not attack technique alone. Ask: if this exploit succeeded, could we reconstruct the full chain of agent decisions and tool calls within 24 hours? An ASI10 Rogue Agent deployment with TA:H and no reasoning trace is especially dangerous — scope of compromise cannot be bounded after detection.",
            "Assessment guidance. Evaluate TD from deployment architecture, not attack technique alone. Ask: if this exploit succeeded, could we reconstruct the full chain of agent decisions and tool calls within 24 hours? An ASI10 Rogue Agent deployment with TD:H and no reasoning trace is especially dangerous — scope of compromise cannot be bounded after detection.",
            True,
        ),
        (
            "10.6 Vector syntax",
            "10.9 Vector syntax",
            True,
        ),
        (
            "AIVSS extends the CVSS v4.0 vector with an optional Agentic AI metric group:\n",
            VECTOR_SYNTAX_BLOCK,
            True,
        ),
        (
            "Identity rule: A0 implies `AIVSS = CVSS-BTE` exactly, in both Mode 1 and Mode 2. Verified in the reference implementation over representative vectors and exhaustive A0 promotion invariance across all 270 MacroVector classes.",
            "Identity rule: A0 implies `AIVSS = CVSS-BTE` exactly in Mode 1. Verified in the reference implementation over representative vectors.",
            True,
        ),
        (
            "Table 20 tabulates the full calculator output for the ASI06 memory-poisoning worked example — MacroVector, interpolated CVSS-BTE, AI class, Mode 1 and Mode 2 scores, exploitation rung, and timelines.",
            "Table 20 tabulates the full calculator output for the ASI06 memory-poisoning worked example — MacroVector, interpolated CVSS-BTE, AI class, Mode 1 AIVSS score, exploitation rung, and timelines.",
            True,
        ),
        (
            "Mode 1–2 and decision-track rows are emitted by:",
            "Mode 1 and decision-track rows are emitted by:",
            True,
        ),
        (
            "5. An expert-ranking exercise to replace the Mode 2 strawman generator (Section 13.2).",
            "5. Continued expert review of assurance-metric rubrics (EX, PT, CA, TD) and inter-rater reliability (Section 17).",
            True,
        ),
        (
            "5. Mode 2 calibration — Replace strawman MacroVector promotion (Section 13.2) with expert-ranked lookup when available.",
            "5. Rubric calibration — Refine EX, PT, CA, and TD value definitions with practitioner feedback.",
            True,
        ),
        (
            "5. Mode 2 provisional. AIVSS-BTEA (Mode 2) is experimental and MUST NOT be used in contracts, SLAs, or regulatory filings without explicit expert calibration.",
            "5. Withdrawn constructs. Mode 2 MacroVector promotion and additive EX+PT+CA+TD severity uplift are not part of AIVSS 1.0 normative scoring.",
            True,
        ),
        # TA -> TD in taxonomy sections (targeted)
        (
            "retained not as a scored risk category but as TA (Traceability Avoidance), a mandatory non-scoring metric",
            "retained not as a scored risk category but as TD (Traceability Deficit), a mandatory parallel metadata metric",
            True,
        ),
        (
            "underscoring why TA assessment remains mandatory in every conformant AIVSS finding (Section 7)",
            "underscoring why TD assessment remains mandatory in every conformant AIVSS finding (Section 7)",
            True,
        ),
        (
            "which AIVSS retains as the mandatory TA risk factor (Section 5.6)",
            "which AIVSS retains as the mandatory TD risk factor (Section 5.6)",
            True,
        ),
        (
            "Agent Untraceability lives on as TA. See Sections 5.1–5.5",
            "Agent Untraceability lives on as TD. See Sections 5.1–5.5",
            True,
        ),
        (
            "retained AIVSS risk factor carried forward as the TA (Traceability Avoidance) metric (Section 5.6, Section 10.5).",
            "retained AIVSS risk factor carried forward as the TD (Traceability Deficit) metric (Section 5.6, Section 10.8).",
            True,
        ),
        (
            "retaining Agent Untraceability as TA (Section 5.6, Section 10.5).",
            "retaining Agent Untraceability as TD (Section 5.6, Section 10.8).",
            True,
        ),
        (
            "How AIVSS measures it. Agent Untraceability is assessed through the TA (Traceability Avoidance) metric in the Agentic AI Profile (Section 10.5). TA is a mandatory risk factor in every conformant assessment (Section 7): assessors MUST evaluate and record TA even though it does not change the Mode 1 severity number.",
            "How AIVSS measures it. Agent Untraceability is assessed through the TD (Traceability Deficit) metric in the Agentic AI Profile (Section 10.8). TD is a mandatory risk factor in every conformant assessment (Section 7): assessors MUST evaluate and record TD even though it does not change the Mode 1 severity number.",
            True,
        ),
        (
            "TA:H SHOULD trigger enhanced incident-response procedures",
            "TD:H SHOULD trigger enhanced incident-response procedures",
            True,
        ),
        (
            "a finding may be ASI02 Tool Misuse with TA:H if the deployment lacks auditability. Classify the primary flaw under ASI01–ASI10; always assess TA separately.",
            "a finding may be ASI02 Tool Misuse with TD:H if the deployment lacks auditability. Classify the primary flaw under ASI01–ASI10; always assess TD separately.",
            True,
        ),
        (
            "Table 7 records the version 1.0 taxonomy decision — adopting OWASP ASI01–ASI10, retiring the parallel AIVSS core-risk list, and retaining Agent Untraceability as the TA metric.",
            "Table 7 records the version 1.0 taxonomy decision — adopting OWASP ASI01–ASI10, retiring the parallel AIVSS core-risk list, and retaining Agent Untraceability as the TD metric.",
            True,
        ),
        (
            "to its OWASP ASI successor (or to TA for Agent Untraceability)",
            "to its OWASP ASI successor (or to TD for Agent Untraceability)",
            True,
        ),
        (
            "showing how each was adopted into OWASP ASI or retained as the TA metric in version 1.0.",
            "showing how each was adopted into OWASP ASI or retained as the TD metric in version 1.0.",
            True,
        ),
        (
            "Survey rankings do not enter any score formula. They explain why the taxonomy emphasizes certain risks and why Agent Untraceability remains a first-class AIVSS concern via TA.",
            "Survey rankings do not enter any score formula. They explain why the taxonomy emphasizes certain risks and why Agent Untraceability remains a first-class AIVSS concern via TD.",
            True,
        ),
        (
            "always deep-dive ASI01, ASI02, and TA logging architecture).",
            "always deep-dive ASI01, ASI02, and TD logging architecture).",
            True,
        ),
        (
            "Practitioners SHOULD cross-reference multiple taxonomies. AIVSS 1.0 uses OWASP ASI01–ASI10 for classification and retains Agent Untraceability as TA (Section 5.6).",
            "Practitioners SHOULD cross-reference multiple taxonomies. AIVSS 1.0 uses OWASP ASI01–ASI10 for classification and retains Agent Untraceability as TD (Section 5.6).",
            True,
        ),
        (
            "2. Inter-rater reliability — Periodic studies across LC, CP, AP, SR, TA with Krippendorff's α",
            "2. Inter-rater reliability — Periodic studies across LC, CP, AP, SR, EX, PT, CA, TD with Krippendorff's α",
            True,
        ),
        (
            "Table 23 recommends release-blocking conditions keyed to AIVSS score bands, Agentic AI Effect Class, TA level, and specific ASI/SR combinations",
            "Table 23 recommends release-blocking conditions keyed to AIVSS score bands, Agentic AI Effect Class, TD level, and specific ASI/SR combinations",
            True,
        ),
        (
            "log approver identity, prompt shown, and tool calls authorized (reduces TA).",
            "log approver identity, prompt shown, and tool calls authorized (reduces TD).",
            True,
        ),
        (
            "Agentic AI Profile. The structured extension to a CVSS assessment comprising the Agentic AI metric group (LC, CP, AP, SR, TA), its vector fragment, and the derived Agentic AI Effect Class. In JSON report output, serialized as the `ai_profile` object (Appendix A).",
            "Agentic AI Profile. The structured extension comprising the eight-metric aivss_vector (LC, CP, AP, SR, EX, PT, CA, TD) and the derived Agentic AI Effect Class. In JSON report output, serialized as the `ai_profile` object with separate `cvss_vector` and `aivss_vector` fields (Appendix A).",
            True,
        ),
        (
            "Credit. TA implements Agent Untraceability",
            "Credit. TD implements Agent Untraceability",
            True,
        ),
        (
            "reinforcing why TA assessment is mandatory in every conformant assessment (Section 7) regardless of whether it modifies the Mode 1 severity number.",
            "reinforcing why TD assessment is mandatory in every conformant assessment (Section 7) regardless of whether it modifies the Mode 1 severity number.",
            True,
        ),
        (
            "indirect goal hijack via poisoned documents the agent retrieves without user action → LC), ASI06 (persistent poisoned context → CP), ASI07 (cross-agent instruction relay → AP), and Agent Untraceability (no OWASP ASI equivalent → TA).",
            "indirect goal hijack via poisoned documents the agent retrieves without user action → LC), ASI06 (persistent poisoned context → CP), ASI07 (cross-agent instruction relay → AP), and Agent Untraceability (no OWASP ASI equivalent → TD).",
            True,
        ),
    ]


def main() -> int:
    verify_account()
    doc = get_doc()
    rev = doc["revisionId"]

    # Batch 1: text replacements (split if payload too large)
    reps = text_replacements()
    # One replacement per batch to stay under Windows CLI length limits.
    n = 0
    for old, new, mc in reps:
        if not old:
            continue
        n += 1
        doc = get_doc()
        rev = doc["revisionId"]
        batch_update(rev, [replace_all(old, new, mc)], f"replacement {n}")
        time.sleep(0.5)

    # Batch 2: delete Section 13.2
    doc = get_doc()
    rev = doc["revisionId"]
    try:
        start, end = find_range(doc, "13.2 Mode 2", "14 OWASP Top 10")
        batch_update(
            rev,
            [{"deleteContentRange": {"range": {"startIndex": start, "endIndex": end, "tabId": TAB_ID}}}],
            "delete section 13.2",
        )
        time.sleep(1)
    except KeyError as e:
        print(f"skip delete 13.2: {e}")

    # Batch 3: rename Section 13 heading and insert withdrawal note + subsections + ref impl
    doc = get_doc()
    rev = doc["revisionId"]
    requests: list[dict] = []

    try:
        batch_update(
            rev,
            [
                replace_all("13 Scoring Modes", "13 Scoring Mode (Mode 1 normative)", True),
                replace_all("13.1 Mode 1 — Interpretation (normative)", "13.1 Mode 1 — CVSS-BTE (normative)", True),
            ],
            "rename section 13",
        )
        time.sleep(1)
        doc = get_doc()
        rev = doc["revisionId"]
    except Exception as e:
        print(f"section 13 rename: {e}")

    # Insert withdrawal note after v0.8 supersession paragraph
    doc = get_doc()
    rev = doc["revisionId"]
    anchor = "New governance structures. Version 1.0 introduces"
    try:
        idx = find_index(doc, anchor)
        batch_update(
            rev,
            [{"insertText": {"location": {"index": idx, "tabId": TAB_ID}, "text": WITHDRAWAL_NOTE}}],
            "insert withdrawal note",
        )
        time.sleep(1)
    except KeyError as e:
        print(f"withdrawal note: {e}")

    # Insert EX/PT/CA subsections before 10.8 TD
    doc = get_doc()
    rev = doc["revisionId"]
    try:
        idx = find_index(doc, "10.8 TD — Traceability Deficit")
        batch_update(
            rev,
            [{"insertText": {"location": {"index": idx, "tabId": TAB_ID}, "text": EIGHT_METRIC_SUBSECTIONS}}],
            "insert EX PT CA subsections",
        )
        time.sleep(1)
    except KeyError as e:
        print(f"metric subsections: {e}")

    # Insert reference implementation body under Section 18
    doc = get_doc()
    rev = doc["revisionId"]
    try:
        idx = find_index(doc, "18 Reference Implementation")
        # insert after heading line — find end of heading paragraph
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
            if "18 Reference Implementation" in text:
                idx = el["endIndex"]
                break
        batch_update(
            rev,
            [{"insertText": {"location": {"index": idx, "tabId": TAB_ID}, "text": REF_IMPL_BODY}}],
            "insert ref impl pin",
        )
    except KeyError as e:
        print(f"ref impl: {e}")

    print("remediation complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
