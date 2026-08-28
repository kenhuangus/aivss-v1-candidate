# AIVSS Scoring Model (v1.0)

Reference for the `aivss-calc` implementation. Normative full specification is maintained separately; this document defines the calculator behavior.

## Mode 1 — Interpretation (normative)

```
CVSS-BTE  = interpolated CVSS v4.0 Base + Threat + Environmental score
TD_delta  = { TD:H → 0.5, TD:M → 0.2, TD:L → 0.0 }
AIVSS     = min(10.0, CVSS-BTE + TD_delta)
```

**TD (Traceability Deficit / Agent Untraceability)** is a mandatory risk factor in every conformant assessment. It reflects operational risk when post-incident reconstruction of agent reasoning and tool actions is infeasible. Higher traceability deficit increases the published AIVSS score because scope of compromise cannot be bounded.

LC, CP, AP, and SR do **not** modify the Mode 1 numeric score. They determine the **AI Effect Class** (A0 / A1 / A2), which feeds Mode 2 and remediation escalation.

## Mode 2 — MacroVector extension (provisional)

```
BTEA_before_TD = min(10, CVSS-BTE + MacroVector_ceiling_delta(AI Effect Class))
AIVSS-BTEA     = min(10, BTEA_before_TD + TD_delta)
```

MacroVector promotion follows S2 equivalence-class promotion (EQ3 and EQ0 for A2). TD_delta uses the same rubric as Mode 1.

## Decision track

BOD 26-04 Table 1 is applied unmodified for the compliance timeline. The AIVSS overlay may advance remediation by:

| Factor | Overlay escalation |
|--------|-------------------|
| AI Effect Class A2 | +1 tier (max 3D) |
| TD:H | +1 tier (max 3D) |

AIVSS never escalates into **3DF** (forensic triage); that remains a CISA KEV determination.

## AIVSS-P (Level 3)

Organizational priority uses the **TD-adjusted** Mode 1 `aivss` as the severity term:

```
AIVSS-P = 100 × geometric_mean(aivss/10, business_criticality, reach, likelihood)
```

## TD value rubric

| Value | Label | Risk delta | Meaning |
|-------|-------|------------|---------|
| TD:H | High deficit | +0.5 | No reasoning trace or tool audit; reconstruction infeasible |
| TD:M | Moderate deficit | +0.2 | Partial logging; reconstruction requires significant effort |
| TD:L | Low deficit | +0.0 | Prompt, trace, and tool-call logging retained and queryable |
