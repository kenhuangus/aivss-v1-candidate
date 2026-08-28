# AIVSS Scoring Model (v1.0)

Reference for the `aivss-calc` calculator. All terminology below is **agentic-application-specific** — AIVSS scores vulnerabilities in autonomous and semi-autonomous agent systems, not generic machine-learning models.

## Definitions

### Agentic AI Profile

The extension to a CVSS v4.0 assessment that captures agent-specific properties CVSS does not name explicitly. It comprises five **Agentic AI metrics** appended to the vector string:

| Metric | Name | Role |
|--------|------|------|
| **LC** | Language-Mediated Control | How attacker-controlled natural language reaches privileged agent behaviour |
| **CP** | Context Persistence | How long attacker-controlled context survives across turns or sessions |
| **AP** | Agentic Propagation | Whether compromise crosses trust boundaries to other agents or tenants |
| **SR** | Stochastic Exploit Reliability | How reproducibly the attack succeeds under retry |
| **TD** | Traceability Deficit | Whether post-incident reconstruction of agent reasoning and tool calls is feasible |

LC, CP, AP, and SR are **scored together** (all four present or all absent). **TD is mandatory** in every conformant assessment.

### Agentic Effect Class (A0 / A1 / A2)

A three-level ordinal label describing **how substantially agentic behaviour amplifies the security consequence** beyond what CVSS alone expresses. It is derived from LC, CP, AP, and SR by a **boolean ladder** — never by arithmetic on metric values.

| Class | Label | Meaning | Derivation (any one rule yields the class) |
|-------|-------|---------|---------------------------------------------|
| **A0** | Absent | No agentic amplification beyond CVSS | All four scored metrics at benign values (LC:N, CP:N, AP:N, SR:U), or scored group absent |
| **A1** | Present | Agentic factors elevate concern | At least one scored metric above benign, and no A2 rule matched |
| **A2** | Substantial | Agentic factors materially worsen impact | `AP:L` (lateral propagation), or `LC∈{D,I}` with `CP:C` (persistent language-mediated control), or `LC:D` with `SR:R` (reliable direct language control) |

Agentic Effect Class feeds Mode 2 MacroVector promotion and may advance the remediation overlay when **A2**.

TD does **not** change Agentic Effect Class; it adjusts the numeric risk score directly (see below).

---

## Mode 1 — Interpretation (normative)

```
CVSS-BTE  = interpolated CVSS v4.0 Base + Threat + Environmental score
TD_delta  = { TD:H → 0.5, TD:M → 0.2, TD:L → 0.0 }
AIVSS     = min(10.0, CVSS-BTE + TD_delta)
```

**TD (Traceability Deficit)** reflects operational risk when scope of compromise cannot be bounded after an agent incident. Higher deficit increases the published AIVSS score.

LC, CP, AP, and SR determine **Agentic Effect Class** only; they do not modify the Mode 1 numeric score.

## Mode 2 — MacroVector extension (provisional)

```
BTEA_before_TD = min(10, CVSS-BTE + MacroVector_ceiling_delta(Agentic Effect Class))
AIVSS-BTEA     = min(10, BTEA_before_TD + TD_delta)
```

MacroVector promotion follows S2 equivalence-class promotion (EQ3 and EQ0 for A2).

## Decision track

BOD 26-04 Table 1 is applied unmodified for the compliance timeline. The AIVSS overlay may advance remediation by:

| Factor | Overlay escalation |
|--------|-------------------|
| Agentic Effect Class **A2** | +1 tier (max 3D) |
| **TD:H** | +1 tier (max 3D) |

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
