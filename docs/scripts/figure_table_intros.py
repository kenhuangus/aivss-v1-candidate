"""Leading prose for every figure and table in AIVSS 1.0 Google Doc.

Keys for tables match <!--table:KEY--> titles. Figure keys match DIAGRAM_MAP section prefixes.
Use {n} in templates for the runtime table/figure number.
"""

FIGURE_INTROS: dict[str, str] = {
    "6 Architecture Overview": (
        "**Figure {n}** maps the AIVSS 1.0 architecture: Layer 1 computes honest CVSS-BTE severity, "
        "Layer 2 records the Agentic AI Profile and AI Effect Class, and Layer 3 applies the BOD 26-04 "
        "timeline model with optional Mode 2 extended severity and internal AIVSS-P priority."
    ),
    "8 End-to-End Assessment Flow": (
        "**Figure {n}** walks through the end-to-end assessment path — from CVSS vector and optional "
        "Agentic AI Profile through Mode 1 AIVSS scoring, parallel remediation timeline resolution, "
        "and optional Mode 2 BTEA lookup — showing where each output is produced."
    ),
    "11 AI Effect Class": (
        "**Figure {n}** summarizes the boolean AI Effect Class ladder: A2 (substantial agentic amplification), "
        "A1 (present but not substantial), and A0 (no profile or all benign), including the rule that "
        "A2 may advance remediation by one BOD tier."
    ),
    "12 Remediation Timelines": (
        "**Figure {n}** shows how the five BOD 26-04 decision inputs feed a 16-row lookup to yield "
        "3-day, 14-day, 60-day, or defer timelines, and how an A2 AI Effect Class advances the "
        "recommended tier while the unmodified BOD baseline is always reported."
    ),
    "12.3 Exploitation evidence ladder": (
        "**Figure {n}** ranks exploitation evidence from strongest to weakest — CISA KEV, Vulnrichment "
        "active exploitation, organization-observed activity, proof-of-concept, and no evidence — and "
        "notes that EPSS is recorded as dated metadata only, not as a ladder rung (Section 12.3.1)."
    ),
    "13.2 Mode 2 — MacroVector extension": (
        "**Figure {n}** explains optional Mode 2 (AIVSS-BTEA): A0 leaves severity unchanged, A1 promotes "
        "subsequent-system impact (EQ4), and A2 also promotes attack-surface metrics (EQ1), with every "
        "output drawn from FIRST's existing MacroVector lookup table."
    ),
}

TABLE_INTROS: dict[str, str] = {
    "Out-of-scope measurement domains": (
        "**Table {n}** lists measurement domains explicitly excluded from AIVSS — alignment, jailbreak "
        "resistance, content safety, bias, and fairness — and what each domain measures, clarifying why "
        "they are out of scope for cybersecurity severity scoring."
    ),
    "CVSS v4.0 Base metrics": (
        "**Table {n}** defines each CVSS v4.0 Base metric abbreviation used in AIVSS assessments, "
        "its full name, and what intrinsic vulnerability property it captures before environmental "
        "or agentic extensions are applied."
    ),
    "CVSS v4.0 Threat metrics": (
        "**Table {n}** documents the CVSS Threat metric group — currently Exploit Maturity (E) — "
        "and the allowed values assessors use when encoding observed exploitation on the vector string."
    ),
    "MacroVector equivalence groups (EQ1–EQ6)": (
        "**Table {n}** groups CVSS Base metrics into the six equivalence classes (EQ1–EQ6) that "
        "define MacroVector identity in CVSS v4.0 and underpin Mode 2 promotion in Section 13.2."
    ),
    "Parameter Provenance": (
        "**Table {n}** traces every normative AIVSS parameter to its source — whether derived from "
        "FIRST or CISA, asserted by the working group, or calibrated — so readers can see what is "
        "externally anchored versus project-chosen."
    ),
    "OWASP Top 10 for Agentic Applications 2026": (
        "**Table {n}** is the canonical OWASP Agentic AI risk taxonomy adopted by AIVSS 1.0: all ten "
        "ASI01–ASI10 categories with a one-line description of each risk for classification and traceability."
    ),
    "Taxonomy adoption decision": (
        "**Table {n}** records the version 1.0 taxonomy decision — adopting OWASP ASI01–ASI10, "
        "retiring the parallel AIVSS core-risk list, and retaining Agent Untraceability as the TD metric."
    ),
    "Retired AIVSS Core Risks → OWASP ASI": (
        "**Table {n}** crosswalks each retired AIVSS Agentic AI Core Risk category to its OWASP ASI "
        "successor (or to TD for Agent Untraceability), preserving lineage from the OWASP AIVSS project research."
    ),
    "Agentic Factor Disposition": (
        "**Table {n}** shows how each historical agentic amplification factor is scored — wholly in CVSS, "
        "wholly as an AI metric (LC/CP/AP/SR/TD), or split — so assessors do not double-count the same property."
    ),
    "LC — Language-Mediated Control": (
        "**Table {n}** defines the LC metric levels (Direct, Indirect, Mediated, None) and when "
        "attacker-controlled natural language can influence security-relevant agent behaviour."
    ),
    "CP — Context Persistence": (
        "**Table {n}** defines the CP metric levels (Cross-session, Session, None) describing how long "
        "attacker-planted context survives and whether it can affect later sessions or other users."
    ),
    "AP — Agentic Propagation": (
        "**Table {n}** defines the AP metric levels (Lateral, Contained, None) for whether compromise "
        "spreads across trust boundaries to other agents, tenants, or downstream systems."
    ),
    "SR — Stochastic Reliability": (
        "**Table {n}** defines the SR metric levels (Reliable, Probabilistic, Unreliable) for how "
        "reproducibly an attack succeeds and whether the attacker can retry freely."
    ),
    "TD — Traceability Deficit (Agent Untraceability)": (
        "**Table {n}** defines the TD metric levels (High, Medium, Low) for Agent Untraceability — "
        "a mandatory AIVSS risk factor retained from the original OWASP AIVSS taxonomy that does not "
        "change the Mode 1 severity number."
    ),
    "BOD 26-04 Decision Inputs": (
        "**Table {n}** lists the five inputs to the BOD 26-04 remediation model — KEV status, public "
        "exposure, automatable, technical impact, and AI Effect Class — with definitions and authoritative sources."
    ),
    "BOD 26-04 Table 1 (16 rows)": (
        "**Table {n}** reproduces CISA's full 16-row BOD 26-04 lookup: every combination of KEV, exposure, "
        "automatable, and technical impact maps to Fix-on-upgrade, 60-day, 14-day, or 3-day (plus forensic) timelines."
    ),
    "EPSS permitted and prohibited uses": (
        "**Table {n}** contrasts appropriate uses of EPSS alongside an AIVSS assessment with prohibited "
        "uses — EPSS must not select the exploitation ladder rung, set CVSS E, modify Mode 1 severity, or "
        "change the BOD timeline lookup (Section 12.3.1)."
    ),
    "S2 Promotion Rules": (
        "**Table {n}** states the provisional Mode 2 MacroVector promotion rules by AI Effect Class: "
        "which equivalence groups (EQ4 and, at A2, EQ1) advance and when promotion is a no-op."
    ),
    "OWASP Agentic AI Top 10 — Calculator Results": (
        "**Table {n}** presents reference-calculator outputs for one worked example per ASI01–ASI10 category — "
        "showing AIVSS severity, AI Effect Class, and both BOD and AIVSS-recommended remediation timelines."
    ),
    "ASI06 Worked Example": (
        "**Table {n}** tabulates the full calculator output for the ASI06 memory-poisoning worked example — "
        "MacroVector, interpolated CVSS-BTE, AI class, Mode 1 and Mode 2 scores, exploitation rung, and timelines."
    ),
    "AIVSS-P index symbols": (
        "**Table {n}** defines the four symbols in the AIVSS-P organizational priority formula — technical "
        "severity (S), business criticality (BI), deployment reach (REACH), and likelihood (L) — each priced once."
    ),
    "Lifecycle Integration — AIVSS Touchpoints": (
        "**Table {n}** maps SDLC phases (design through production) to recommended AIVSS activities, "
        "required artifacts, and minimum conformance level so teams know when to assess and what to store."
    ),
    "Recommended Release Gates": (
        "**Table {n}** recommends release-blocking conditions keyed to AIVSS score bands, AI Effect Class, "
        "TD level, and specific ASI/SR combinations — translating severity into deploy-or-hold guidance."
    ),
    "AIVSS Mapping to Risk Frameworks": (
        "**Table {n}** explains how AIVSS outputs integrate with NIST RMF, NIST AI RMF, CSA MAESTRO "
        "Agentic AI threat modeling, CISA BOD 26-04, ISO 27001, CVSS/FIRST, and MITRE ATLAS without "
        "claiming endorsement or replacing those frameworks."
    ),
    "AI Threat Taxonomies and References": (
        "**Table {n}** surveys external threat taxonomies and standards — OWASP ASI, MITRE ATLAS, MAESTRO, "
        "KEV, EPSS, NIST, and BOD 26-04 — and how each relates to AIVSS classification, scoring, or timelines."
    ),
    "AIVSS Report — Fields": (
        "**Table {n}** lists report JSON fields by conformance level — Level 1 core fields plus "
        "optional Level 2 `decision` and Level 3 `priority` blocks — with types and semantics."
    ),
    "Contributor Survey — Relative Risk Ranking (AIVSS Core Risks)": (
        "**Table {n}** ranks the original ten AIVSS Agentic AI Core Risks by median contributor impact score "
        "and shows how each was adopted into OWASP ASI or retained as the TD metric in version 1.0."
    ),
}
