# AIVSS v0.9 — CVSS-Compatible AI Scoring

**Status:** Draft for working group review
**Supersedes:** AIVSS v0.8 and the withdrawn v0.9 "Tri-Track" quantitative model
**Canonical taxonomy:** OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)
**Reference implementation:** `tools/aivss-calc` (93 tests, exact assertions)

> This document consolidates the normative specification, completed Appendix E, review-board responses, and reference-tool verification into a single working-group draft.

---

## 1 Executive Summary

AIVSS v0.8 scored agentic findings as `(CVSS_Base + AARS) × Mitigation_Factor`. Appendix E of the v1.00.8 draft records a Distinguished Review Board objection that this construction "is the least defensible mathematically because it risks double-counting, treats ordinal factors as additive, and creates severity inflation without recalibrating the full scoring model." The FIRST.org CVSS FAQ separately states that "AIVSS merges software quality, ethics, privacy, and cybersecurity issues into one-size-fits-all risk measurement" and that "averaging different dimensions creates dangerously misleading perceptions."

**The working group accepts both objections.** Analysis of the v0.8/v0.9 uplift model confirmed them concretely:

- Expanding the formula gives `AIVSS_S = (1 − k)·CVSS_Base + 10k` where `k = Factor_Sum × ThM × MF`. At the framework's own worked-example factor level the coefficient on `CVSS_Base` is **0.1755** — a CVSS 0.1 finding scored 8.3 and a CVSS 9.9 finding scored 10.0.
- The Threat Multiplier's Proof-of-Concept default of 0.97 meant the EPSS term could only ever change the result when EPSS exceeded 0.94. The entire EPSS dimension could move a score by at most 0.1 points.
- The withdrawn `EPSS_AI` construct — four booleans worth 0.25 each — was substituted into a transform designed for a calibrated probability.

**v0.9 adopts Appendix E Option 3:** map everything possible into CVSS, define new metrics only for the AI-specific residual, and integrate through a MacroVector lookup table rather than arithmetic uplift. Prioritization moves out of the severity number entirely and onto CISA BOD 26-04, which since June 10, 2026 is the federal remediation standard.

**Net effect: AIVSS never invents a score.** In Mode 1 the number emitted *is* a CVSS score. In Mode 2 it is a different entry from FIRST's own expert-ranked lookup table. There is no arithmetic path by which AIVSS produces a value the CVSS SIG's process did not produce.

### 1.1 What changed from v0.8

| Area | v0.8 / withdrawn v0.9 | v0.9 (this draft) |
|---|---|---|
| Core formula | Additive uplift on CVSS base | `AIVSS = CVSS-BTE` (Mode 1, normative) |
| AI factors | Weighted arithmetic amplification | LC/CP/AP/SR/TD profile + boolean AI Effect Class |
| Prioritization | Track P geometric mean (88% bottom-band skew) | CISA BOD 26-04 decision track (Level 2) |
| KEV / EPSS | Multiplier terms (`ThM`, `EPSS_AI`) | Evidence ladder + BOD Table 1 lookup |
| Taxonomy | Bespoke 10-category list | OWASP ASI01–ASI10 (2026) |
| Legacy uplift | Normative | Annex B informative only, deprecated at v1.0 |

---

## 2 Architecture Overview

AIVSS v0.9 is organized into three normative parts plus two annexes. Part I interprets agentic properties through CVSS v4.0. Part II defines the AI metric group and AI Effect Class. Part III consumes CISA BOD 26-04 for remediation timelines. Annex A provides a provisional MacroVector extension (Mode 2). Annex B retains the withdrawn uplift model for v0.8 score migration only.

### 2.1 Conformance levels

**Level 1 — Severity and profile.** The tier tools should implement, and sufficient on its own to claim "AIVSS v0.9 conformant."

- MUST supply a CVSS v4.0 Base vector (MAY be imported from NVD or an advisory).
- MUST supply all four scored AI metrics, or explicitly none.
- MUST classify the finding to an ASI01–ASI10 category.
- MUST emit a conformant vector string.
- MAY omit the decision track and AIVSS-P.

**Level 2 — Level 1 plus the decision track.** MUST supply asset exposure (`publicly_exposed`) and MUST report the unmodified BOD 26-04 timeline alongside any AIVSS recommendation.

**Level 3 — Level 2 plus organizational priority.** AIVSS-P outputs are organization-internal. A Level 3 producer MUST NOT publish AIVSS-P outside the assessing organization.

**Consumer conformance.** MUST parse all vector strings at its declared level; MUST NOT display an AIVSS score in a field that also carries CVSS scores without the `AIVSS:` prefix; MUST NOT substitute a missing AI metric group for an all-benign one.

---

## 3 End-to-End Assessment Flow

An AIVSS assessment begins with a CVSS v4.0 Base vector. When AI metrics are present, they are parsed as an optional extension group in fixed order: LC / CP / AP / SR / TD. The tool computes an interpolated CVSS-BTE score (not merely the MacroVector ceiling), classifies the AI Effect Class, and emits Mode 1 (normative) and optionally Mode 2 (provisional) scores. At Level 2, the decision track runs in parallel, consuming BOD 26-04 inputs plus the AI Effect Class.

---

## 4 Scope and Non-Goals

AIVSS scores the security consequences of vulnerabilities in **deployed agentic systems** — systems with tool access, execution autonomy, persistent state, and network reach.

AIVSS does **not** score model alignment, jailbreak resistance, content safety, bias, or fairness. These are distinct measurement problems with distinct methodologies and evidence bases, and the working group agrees with the CVSS SIG that they should not be combined with cybersecurity scoring.

### 4.1 What AIVSS v0.9 does not claim

1. Not comparability with, compatibility with, or endorsement by CVSS or FIRST.
2. Not integration with or endorsement by FIRST (EPSS), CISA (KEV, Vulnrichment), or CMU/SEI CERT (SSVC).
3. Not a probability, not a risk quantification, and not expressible in expected loss.
4. Not empirically validated. **No claim is made that any AIVSS output predicts exploitation.**
5. Not a measure of model safety, alignment, jailbreak resistance, content safety, bias, or ethics.
6. Not SSVC-conformant. AIVSS consumes SSVC decision point *definitions* by reference; it does not publish an SSVC decision tree.
7. Not comparable across organizations, in the case of AIVSS-P.
8. Not a remediation mandate on its own. For FCEB agencies, the operative obligation is BOD 26-04, unmodified.

### 4.2 Parameter provenance

Each value is classified as **derived** (inherited from a calibrated external source), **asserted** (chosen by the working group on argument), or **calibrated** (fitted to data). No parameter in v0.9 is calibrated.

<!--table:Parameter Provenance-->
| Parameter | Value(s) | Status |
|---|---|---|
| CVSS-BTE scores | 270 MacroVector entries | Derived — FIRST cvss_lookup.js |
| MacroVector EQ1–EQ6 boundaries | per CVSS v4.0 §8.2 | Derived — verbatim from FIRST |
| AI metric value levels (LC/CP/AP/SR/TD) | §5 | Asserted — ordinal rubric, no arithmetic |
| AI Effect Class ladder | §5 | Asserted — boolean rule |
| S2 promotion axes (EQ1, EQ4) | Annex A | Asserted — provisional |
| BOD 26-04 Table 1 timelines | 16 rows | Derived — CISA / CERT-CC cisa:BOD2604:1.0.0 |
| A2 escalation of one tier | §6.3 | Asserted — non-binding overlay |
| Annex B uplift constants | ThM, MF | Asserted — v0.8 reproducibility only |

---

## 5 Part I — Interpretation Guide (Normative)

**Core rule.** `AIVSS = CVSS-BTE`. AI metrics are reported as a profile and do not modify the numeric score in Mode 1.

Existing agentic factors are not independently scored unless listed in Part II as a new AI metric. The ten AIVSS v0.8 amplification factors resolve as follows:

<!--table:v0.8 Factor Disposition-->
| v0.8 amplification factor | Disposition |
|---|---|
| Execution Autonomy | CVSS UI / AT. An agent that acts without human confirmation is UI:N. |
| External Tool Control Surface | CVSS SC / SI / SA. Score Subsequent System metrics against full tool reach. |
| Dynamic Identity | CVSS PR plus SC/SI/SA. Score PR at the agent's credential, not the caller's. |
| Contextual Awareness | CVSS AT and scope guidance |
| Natural Language Interface | LC |
| Persistent State Retention | CP |
| Self-Modification | CP, plus CVSS SI where the agent rewrites its own configuration |
| Behavioural Non-Determinism | SR |
| Multi-Agent Interactions | AP |
| Opacity and Reflexivity | TD (supplemental; no score effect) |

### 5.1 The four most common CVSS scoring errors in agentic systems

1. **Under-scoring Subsequent System metrics.** SC/SI/SA must be assessed against the full reach of the agent's tool set, not the process boundary.
2. **Scoring PR at the human's privilege.** Score the agent's effective credential.
3. **Scoring UI:P because a human is nominally in the loop.** If approval is routinely granted without meaningful review, UI:N is the honest value.
4. **Treating retrieval-sourced injection as requiring user interaction.** Content ingested autonomously is not user interaction.

### 5.2 Non-overlap rule

AI metrics MUST NOT rescore a condition already represented in CVSS. If model stochasticity was already encoded as AT:P, do **not** also score SR. Record which representation was used.

---

## 6 Part II — AI Metric Group (Normative)

Scored metrics: **LC**, **CP**, **AP**, **SR**. Supplemental: **TD**.

### 6.1 LC — Language-Mediated Control

<!--table:LC Value Levels-->
| Value | Label | Definition |
|---|---|---|
| LC:D | Direct | Attacker-supplied text reaches a privileged decision or tool-invocation path without mediation. |
| LC:I | Indirect | Attacker-controlled language enters through retrieved or ingested content and influences security-relevant behaviour. |
| LC:M | Mediated | Language influences behaviour only through a constrained interface. |
| LC:N | None | No natural-language path to security-relevant behaviour. |

### 6.2 CP — Context Persistence

<!--table:CP Value Levels-->
| Value | Label | Definition |
|---|---|---|
| CP:C | Cross-session | Persists in long-term memory, vector store, or training data; influences later sessions or other users. |
| CP:S | Session | Persists only within the active session. |
| CP:N | None | Single-turn only. |

### 6.3 AP — Agentic Propagation

<!--table:AP Value Levels-->
| Value | Label | Definition |
|---|---|---|
| AP:L | Lateral | Crosses a trust boundary to other agents, tenants, or downstream systems. |
| AP:C | Contained | Propagates within the agent's own tool and action scope. |
| AP:N | None | Confined to the initially affected component. |

### 6.4 SR — Stochastic Exploit Reliability

<!--table:SR Value Levels-->
| Value | Label | Definition |
|---|---|---|
| SR:R | Reliable | Succeeds on essentially every attempt, or the attacker can retry freely. |
| SR:P | Probabilistic | Succeeds intermittently; retry rate-limited or detectable. |
| SR:U | Unreliable | Rarely reproducible, no practical retry path. |

### 6.5 TD — Traceability Deficit (supplemental)

**TD never affects any numeric score.** It informs response priority, control requirements, and release gating.

<!--table:TD Value Levels-->
| Value | Label | Definition |
|---|---|---|
| TD:H | High deficit | No reasoning trace and no tool-call audit; reconstruction infeasible. |
| TD:M | Moderate deficit | Partial logging; reconstruction possible with effort. |
| TD:L | Low deficit | Prompt, reasoning-trace, and tool-call logging retained and queryable. |

### 6.6 Vector syntax

AIVSS extends the CVSS v4.0 vector with an optional AI metric group:

```text
CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P/LC:D/CP:C/AP:L/SR:R/TD:H
```

All four scored metrics MUST be present together or all absent. TD is optional. An unknown key MUST cause a parse failure. A score MUST be rendered as `AIVSS:7.8`, never as a bare number.

---

## 7 AI Effect Class

The scored metrics produce an AI Effect Class by boolean ladder. No arithmetic is performed.

- **A2 (Substantial)** — AP:L, **or** (LC in {D, I} **and** CP:C), **or** (LC:D **and** SR:R)
- **A1 (Present)** — not A2, and any scored metric above its benign value
- **A0 (None)** — LC:N and CP:N and AP:N and SR:U, or the AI metric group is absent

**A0 implies AIVSS = CVSS-BTE exactly, in both modes.** This is the Appendix E identity rule, verified exhaustively across all 270 MacroVectors (0 violations).

---

## 8 Decision Track (Normative at Level 2)

Severity does not determine remediation urgency. Since June 10, 2026, BOD 26-04 has replaced CVSS-severity-driven federal remediation with a four-variable model. AIVSS consumes that model verbatim and adds one decision point.

<!--table:BOD 26-04 Decision Points-->
| Decision point | Source |
|---|---|
| KEV Status | CISA KEV catalog |
| Automatable | CISA Vulnrichment; if unavailable, derive from SR:R |
| Technical Impact | CISA Vulnrichment; if unavailable, derive from CVSS VC/VI/VA |
| Asset Exposure | Assessing organization (publicly_exposed, required at Level 2) |
| AI Effect Class | AIVSS Part II |

Where CISA has published neither Automatable nor Technical Impact and the CVE is not in KEV, BOD 26-04 directs that they be treated as "no" and "total" respectively. SR/CVSS derivations apply only for non-CVE findings without Vulnrichment data.

### 8.1 BOD 26-04 Table 1

All sixteen rows, transcribed from `cisa:BOD2604:1.0.0`. Held as a lookup table, not boolean logic: the fast tier requires exposure or automatability **in addition to** KEV, so "KEV plus total impact means three days" is wrong for (KEV, not exposed, not automatable, total), which is 14 days.

<!--table:BOD 26-04 Table 1 (16 rows)-->
| In KEV | Publicly Exposed | Automatable | Technical Impact | Timeline |
|---|---|---|---|---|
| no | no | no | partial | Fix on system upgrade |
| no | no | no | total | Fix on system upgrade |
| no | yes | no | partial | 60 days |
| no | no | yes | partial | 60 days |
| no | no | yes | total | 60 days |
| yes | no | no | partial | 14 days |
| yes | yes | no | partial | 14 days |
| yes | no | yes | partial | 14 days |
| no | yes | yes | partial | 14 days |
| yes | no | no | total | 14 days |
| no | yes | no | total | 14 days |
| yes | yes | yes | partial | 3 days |
| no | yes | yes | total | 3 days |
| yes | yes | no | total | 3 days and forensic triage |
| yes | no | yes | total | 3 days and forensic triage |
| yes | yes | yes | total | 3 days and forensic triage |

### 8.2 Exploitation Evidence Ladder

Strict precedence, highest authority first. Replaces the withdrawn `max(ThM_discrete, ThM_EPSS, ThM_KEV)` construction.

1. CVE listed in CISA KEV → **Active** (authoritative)
2. CISA Vulnrichment reports Exploitation: active → **Active** (authoritative)
3. Published EPSS → used **as published**, untransformed, **with observation date** (metadata only; EPSS does not invent PoC or Active states)
4. Exploitation observed and documented by the assessing organization → **Active (unverified)** — the rung for non-CVE agentic findings
5. Proof-of-concept exists → **PoC**
6. No evidence → **None**

There is no `EPSS_AI` and no `AI-KEV`. Both are withdrawn.

### 8.3 AI Effect Class escalation

When the AI Effect Class is **A2**, the recommended timeline advances by exactly one tier: FSU → 60D → 14D → 3D. **Escalation stops at 3D.** AIVSS never escalates into forensic triage. The unmodified BOD 26-04 result MUST always be reported alongside the AIVSS recommendation.

---

## 9 Scoring Modes

### 9.1 Mode 1 — Interpretation (normative)

`AIVSS = CVSS-BTE`. AI metrics are reported as a profile. Immediately usable, zero score inflation, identity trivially preserved. Scoring uses proper CVSS v4 interpolation (not MacroVector ceiling values).

### 9.2 Mode 2 — MacroVector extension (provisional)

`AIVSS-BTEA = Lookup_AIVSS(EQ1..EQ6, A)`. See Annex A. **Provisional pending expert calibration; not for use in contracts, SLAs, or compliance gates.**

---

## 10 Annex A — MacroVector Extension (Provisional)

```
AIVSS-BTEA = Lookup_AIVSS(EQ1, EQ2, EQ3, EQ4, EQ5, EQ6, A)
```

EQ1–EQ6 are the CVSS v4.0 equivalence groups (270 valid classes). A is the AI Effect Class.

### 10.1 The S2 generator

An AI Effect Class does not add a numeric uplift. It **selects a neighbouring MacroVector and returns that MacroVector's existing CVSS score.**

<!--table:S2 Promotion Rules-->
| Class | Promotion |
|---|---|
| A0 | none — identity |
| A1 | EQ4 → max(0, EQ4 − 1) |
| A2 | EQ4 → max(0, EQ4 − 1) and EQ1 → max(0, EQ1 − 1) |

EQ4 (SC/SI/SA) is promoted because subsequent-system impact is the dimension agentic persistence and propagation extend. EQ1 (AV/PR/UI) is additionally promoted at A2 because substantial language-mediated control effectively removes privilege and interaction barriers.

**This generator invents no numbers.** Every AIVSS-BTEA value already exists in FIRST's expert-ranked `cvss_lookup.js`.

### 10.2 Verified properties

Checked exhaustively across all 270 MacroVectors:

- **Identity:** Lookup_AIVSS(EQ, A0) == CVSS-BTE — 0 violations.
- **Monotone:** promotion never lowers a score — 0 violations.
- **Closed:** every promoted MacroVector is a valid class.
- **Bounded:** AIVSS-BTEA ≤ 10.0.
- **Ordered:** A2 ≥ A1 ≥ A0 for every MacroVector.

### 10.3 Known limitation

Promotion is coarse. A1 is a no-op for the 90 MacroVectors already at EQ4 = 0; A2 is a full no-op for the 30 already at both EQ1 = 0 and EQ4 = 0 — 11% of the space. Saturation is reported explicitly in the tool output.

---

## 11 Annex B — Withdrawn Uplift Model (Informative)

**Deprecated. Scheduled for removal at v1.0.** Retained solely so organizations holding v0.8 scores can reproduce and migrate them.

```
AIVSS_S = CVSS_Base + (AARS × MF)          where AARS = (10 − CVSS_Base) × Factor_Mean × ThM
```

Two changes from v0.8: (1) the mitigation factor applies to the uplift only, guaranteeing `CVSS_Base ≤ AIVSS_S ≤ 10.0`; (2) the category weight table is withdrawn — the factor mean is now unweighted.

---

## 12 Appendix E — Completed Sections

Appendix E of the v1.00.8 draft proposed Option 3 but left four sections incomplete: the mandatory mapping table (§2), metric value levels (§3), the A1/A2 derivation rule (§4), and the strawman lookup table (§6). This draft supplies all four.

**Governing rule (adopted verbatim):** Map everything possible into CVSS. Score only the AI-specific residual. If scoring is needed, integrate AI through a MacroVector lookup table — not through agentic uplift.

**Taxonomy switch:** OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10), published December 9, 2025. The bespoke v0.8 list had no equivalent for ASI09 (Human–Agent Trust Exploitation) or ASI10 (Rogue Agents). "Agent Untraceability" has no ASI successor — traceability is carried as the supplemental TD metric.

---

## 13 Review Board Findings and Responses

This section records the quantitative findings that drove the architectural pivot, with the v0.9 response for each.

### 13.1 EPSS integration was inert

**Finding.** ThM for Proof-of-Concept is 0.97 (the default). ThM_EPSS = 0.50 + 0.50 × EPSS. Under max() selection, EPSS could only change the result when EPSS > 0.94. Maximum effect of the entire EPSS dimension: 0.1 points.

**Response.** EPSS removed from exploitation precedence. Recorded as metadata with observation date only. Strict evidence ladder adopted (§8.2).

### 13.2 CVSS base was attenuated to near-irrelevance

**Finding.** At the draft's worked-example factor level, the coefficient on CVSS_Base is 0.1755. A CVSS 0.1 finding scored 8.3 and a CVSS 9.9 finding scored 10.0. Over a uniform grid, 33% came out Critical.

**Response.** Uplift model withdrawn to Annex B. Mode 1 identity rule: AIVSS = CVSS-BTE with no arithmetic modification.

### 13.3 Appendix E Option 3 adopted as architecture

**Finding.** Appendix E raises a correctness objection. Sequencing the uplift as Phase 1 does not resolve it.

**Response.** Three-part normative architecture (Parts I–III) plus Annex A (provisional) and Annex B (informative). Appendix E reproduced, not paraphrased into a roadmap.

### 13.4 KEV leveraged through BOD 26-04

**Finding.** Treating KEV as a 1.00 multiplier term discards BOD 26-04's four-variable model and mandatory timelines.

**Response.** BOD 26-04 consumed verbatim as 16-row lookup. AI Effect Class added as fifth decision point with one-tier escalation.

### 13.5 Withdrawn constructs

**Withdrawn:** `EPSS_AI`, `AI-KEV`, `SSVC-AI`. Each borrowed an owning organization's name for an artifact lacking the property the name asserts.

### 13.6 Decision procedure emitted only two of three outcomes

**Finding.** The Attend rule fired on AIVSS-S ≥ 4.0 OR (ThM ≥ 0.97 AND Tools ≥ 0.5). "Track" was unreachable for every score from 0.0 to 10.0.

**Response.** Replaced entirely by BOD 26-04's five tiers.

### 13.7 Risk Amplification Matrix weights withdrawn

**Finding.** Normative weights referenced a matrix that was never published. Identical technical facts produced a 1.92× spread from the category label alone.

**Response.** Weights withdrawn. Category label informs taxonomy (ASI01–ASI10) only; it does not enter any score formula.

---

## 14 Worked Example — ASI06 Memory and Context Poisoning

**Finding:** ASI06 Memory and Context Poisoning. Attacker-controlled text reaches a tool-invocation path directly, persists in the shared vector store across sessions, propagates to sibling agents, and reproduces reliably. No reasoning trace is retained.

```text
CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P/LC:D/CP:C/AP:L/SR:R/TD:H
```

<!--table:Worked Example Outputs-->
| Output | Value |
|---|---|
| MacroVector | 011110 |
| MacroVector ceiling | 8.0 |
| CVSS-BTE (interpolated) | 7.8 |
| AI Effect Class | A2 (AP:L; also LC:D+CP:C; also LC:D+SR:R) |
| Mode 1 — AIVSS | 7.8 (normative) |
| Mode 2 — AIVSS-BTEA | 9.0 via promoted MacroVector 011010 (provisional) |
| Exploitation rung | PoC |
| Automatable | yes (derived from SR:R) |
| Technical Impact | total (derived from VC:H) |
| BOD 26-04 timeline | 3 days |
| AIVSS recommendation | 3 days (already at ceiling; no escalation) |
| AIVSS-P (BI high, reach high, L 0.72) | 87 — Immediate |

Every number above is emitted by the reference implementation:

```bash
cd tools/aivss-calc && pip install -e ".[dev]"
aivss-calc verify
aivss-calc assess examples/asi06-memory-poisoning.json
pytest
```

---

## 15 AIVSS-P — Organizational Priority (Level 3, Optional)

Organization-internal and non-portable.

```
AIVSS-P = 100 × geometric_mean(S/10, BI, REACH, L)
```

Each quantity is priced exactly once: S is technical severity, BI business criticality, REACH deployment reach, L organization-assessed likelihood. Exploitation appears nowhere — that belongs to the decision track.

Band cut-points (p90 / p65 / p35 of a uniform grid, n = 10,980): **Immediate ≥ 78, This sprint ≥ 64, Scheduled ≥ 53, Backlog below 53.**

---

## 16 Governance and Calibration Commitments

The working group commits to publishing, before v1.0:

1. A conformance test-vector file with exact expected outputs and zero tolerance.
2. A score distribution over a corpus of at least 200 assessed findings.
3. An inter-rater reliability study: at least 20 findings × 8 assessors, with Krippendorff's α reported per AI metric.
4. A change-control policy: semantic versioning, public issue tracker, minimum 12-month deprecation notice.
5. An expert-ranking exercise to replace the Annex A strawman.

---

## 17 Open Questions for the Review Board

1. Are the three A2 clauses in §7 the right boolean conditions?
2. Are EQ4 and EQ1 the right S2 promotion axes, or should A2 promote EQ4 twice?
3. Should the bounded-offset generator (§Annex A rejected alternative) be preferred for finer granularity?
4. Does the board want AIVSS in the remediation-timeline business at all, or should the decision track stay advisory?
5. Is the SR/AT non-overlap rule sufficient, or should SR be dropped when AT is present?

---

## References

1. FIRST. CVSS v4.0 Specification Document, §8.2 MacroVectors. https://www.first.org/cvss/v4.0/specification-document
2. FIRST. cvss_lookup.js, CVSS v4.0 calculator reference implementation.
3. CISA. BOD 26-04: Prioritizing Security Updates Based on Risk, June 10, 2026.
4. CISA. Reducing the Significant Risk of Known Exploited Vulnerabilities (KEV criteria).
5. CERT/CC. SSVC: CISA BOD 26-04 Response Model (cisa:BOD2604:1.0.0).
6. OWASP GenAI Security Project. Top 10 for Agentic Applications 2026 (ASI01–ASI10), December 9, 2025. https://genai.owasp.org/
7. NIST SP 800-30 Rev. 1. Guide for Conducting Risk Assessments.
8. AIVSS v1.00.8 draft, Appendix E — AIVSS v2 Proposal: CVSS-Compatible AI Scoring.
