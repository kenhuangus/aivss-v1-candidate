# AIVSS v0.9 — CVSS-Compatible AI Scoring

**Status:** Draft for working group review
**Supersedes:** AIVSS v0.8, and the withdrawn v0.9 "Tri-Track" quantitative model
**Canonical taxonomy:** OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)

---

## 0. Summary of what changed and why

AIVSS v0.8 scored agentic findings as `(CVSS_Base + AARS) × Mitigation_Factor`. Appendix E of the v1.00.8 draft records a Distinguished Review Board objection that this construction "is the least defensible mathematically because it risks double-counting, treats ordinal factors as additive, and creates severity inflation without recalibrating the full scoring model." The FIRST.org CVSS FAQ separately states that "AIVSS merges software quality, ethics, privacy, and cybersecurity issues into one-size-fits-all risk measurement" and that "averaging different dimensions creates dangerously misleading perceptions."

**The working group accepts both objections.** Analysis of the v0.8/v0.9 uplift model confirmed them concretely:

- Expanding the formula gives `AIVSS_S = (1 − k)·CVSS_Base + 10k` where `k = Factor_Sum × ThM × MF`. At the framework's own worked-example factor level the coefficient on `CVSS_Base` is **0.1755** — a CVSS 0.1 finding scored 8.3 and a CVSS 9.9 finding scored 10.0. Roughly a third of a uniform input grid came out Critical.
- The Threat Multiplier's Proof-of-Concept default of 0.97 meant the EPSS term could only ever change the result when EPSS exceeded 0.94. The entire EPSS dimension could move a score by at most 0.1 points.
- The withdrawn `EPSS_AI` construct — four booleans worth 0.25 each — was substituted into a transform designed for a calibrated probability.

v0.9 therefore adopts **Appendix E Option 3**: map everything possible into CVSS, define new metrics only for the AI-specific residual, and integrate through a MacroVector lookup table rather than arithmetic uplift. Prioritization moves out of the severity number entirely and onto CISA BOD 26-04, which since June 10, 2026 is the federal remediation standard.

**Net effect: AIVSS never invents a score.** In Mode 1 the number emitted *is* a CVSS score. In Mode 2 it is a different entry from FIRST's own expert-ranked lookup table. There is no arithmetic path by which AIVSS produces a value the CVSS SIG's process did not produce.

---

## 1. Scope and non-goals

AIVSS scores the security consequences of vulnerabilities in **deployed agentic systems** — systems with tool access, execution autonomy, persistent state, and network reach.

AIVSS does **not** score model alignment, jailbreak resistance, content safety, bias, or fairness. These are distinct measurement problems with distinct methodologies and evidence bases, and the working group agrees with the CVSS SIG that they should not be combined with cybersecurity scoring. Where a model-behaviour severity framework is in use, its output may inform the exploitation evidence ladder in §7, but it does not enter any AIVSS score.

### 1.1 What AIVSS v0.9 does not claim

1. Not comparability with, compatibility with, or endorsement by CVSS or FIRST. AIVSS takes a CVSS v4.0 vector as a required input; it does not extend CVSS.
2. Not integration with or endorsement by FIRST (EPSS), CISA (KEV, Vulnrichment), or CMU/SEI CERT (SSVC). AIVSS consumes their published outputs under their own definitions.
3. Not a probability, not a risk quantification, and not expressible in expected loss.
4. Not empirically validated. **No claim is made that any AIVSS output predicts exploitation.**
5. Not a measure of model safety, alignment, jailbreak resistance, content safety, bias, or ethics.
6. Not an endorsement of the OWASP Risk Rating Methodology or CWSS as current practice (see §11).
7. Not SSVC-conformant. AIVSS consumes SSVC decision point *definitions* by reference; it does not publish an SSVC decision tree.
8. Not comparable across organizations, in the case of AIVSS-P (§9).
9. Not a remediation mandate on its own. For FCEB agencies, the operative obligation is BOD 26-04, unmodified.

---

## 2. Provenance of every parameter

Each value below is classified as **derived** (inherited from a calibrated external source), **asserted** (chosen by the working group on argument), or **calibrated** (fitted to data). No parameter in v0.9 is calibrated.

| Parameter | Value(s) | Status |
|---|---|---|
| CVSS-BTE scores | 270 MacroVector entries | **Derived** — verbatim from FIRST `cvss_lookup.js`, expert-ranked |
| MacroVector EQ1–EQ6 boundaries | per CVSS v4.0 §8.2 | **Derived** — verbatim from FIRST |
| AI metric value levels (LC/CP/AP/SR/TD) | §5 | **Asserted** — ordinal rubric levels, spacing never used in arithmetic |
| AI Effect Class ladder | §6 | **Asserted** — boolean rule, no arithmetic |
| S2 promotion axes (EQ1, EQ4) | Annex A | **Asserted** — chosen for semantic fit and constraint safety |
| BOD 26-04 Table 1 timelines | 16 rows | **Derived** — verbatim from CISA / CERT-CC `cisa:BOD2604:1.0.0` |
| A2 escalation of one tier | §7.3 | **Asserted** — non-binding overlay, capped below forensic triage |
| AIVSS-P context levels | 1.0 / 0.65 / 0.35 | **Asserted** |
| AIVSS-P band cut-points | 78 / 64 / 53 | **Asserted**, but set from the observed output distribution (§9.2) |
| Annex B uplift constants | ThM, MF | **Asserted** — inherited unchanged from v0.8 for reproducibility only |

### 2.1 Statistical caveat

AIVSS inputs are **ordinal**. The AI metric levels are rubric categories, not measured quantities, and their letter codes carry no claim that "Indirect" sits exactly halfway between "None" and "Direct."

This is why v0.9 performs no arithmetic on them. The AI Effect Class is a boolean ladder; Mode 2 is a table lookup. Nowhere in the normative model is an ordinal AI metric value summed, averaged, or multiplied. That is the substantive difference from v0.8 and the direct answer to Appendix E's "treats ordinal factors as additive" objection.

Note the asymmetry a reviewer will press, and which the working group concedes: CVSS v4's lookup table is arithmetic-free *by construction*, whereas AIVSS's promotion rule is an asserted mapping between equivalence classes. Annex A is provisional for exactly this reason.

---

## 3. Conformance

**Level 1 — Severity and profile.** The tier tools should implement, and sufficient on its own to claim "AIVSS v0.9 conformant."

- MUST supply a CVSS v4.0 Base vector, which MAY be imported from a vendor, NVD, or advisory rather than independently assessed.
- MUST supply all four scored AI metrics, or explicitly none.
- MUST classify the finding to an ASI01–ASI10 category.
- MUST emit a conformant vector string (§5.6).
- MAY omit the decision track and AIVSS-P.

**Level 2 — Level 1 plus the decision track.** MUST supply asset exposure and MUST report the unmodified BOD 26-04 timeline alongside any AIVSS recommendation.

**Level 3 — Level 2 plus organizational priority.** AIVSS-P outputs are organization-internal. A Level 3 producer MUST NOT publish AIVSS-P outside the assessing organization.

**Consumer conformance.** MUST parse all vector strings at its declared level; MUST NOT display an AIVSS score in a field or column that also carries CVSS scores without the `AIVSS:` prefix; MUST NOT substitute a missing AI metric group for an all-benign one.

---

## 4. Part I — Interpretation guide (normative)

**Core rule.** `AIVSS = CVSS-BTE`. AI metrics are reported as a profile and do not modify the numeric score.

Existing agentic factors are not independently scored unless listed in §5 as a new AI metric. The ten AIVSS v0.8 amplification factors resolve as follows:

| v0.8 amplification factor | Disposition |
|---|---|
| Execution Autonomy | → CVSS `UI` / `AT`. An agent that acts without human confirmation is `UI:N`. |
| External Tool Control Surface | → CVSS `SC` / `SI` / `SA`. Score the Subsequent System metrics against everything the agent's tools can reach. |
| Dynamic Identity | → CVSS `PR` plus `SC`/`SI`/`SA`. Score `PR` at the privilege the agent's credential actually carries, not the caller's. |
| Contextual Awareness | → CVSS `AT` and scope guidance. |
| Natural Language Interface | → **LC** |
| Persistent State Retention | → **CP** |
| Self-Modification | → **CP**, plus CVSS `SI` where the agent rewrites its own configuration |
| Behavioural Non-Determinism | → **SR** |
| Multi-Agent Interactions | → **AP** |
| Opacity & Reflexivity | → **TD** (supplemental; no score effect) |

### 4.1 The most common CVSS scoring errors in agentic systems

1. **Under-scoring Subsequent System metrics.** `SC`/`SI`/`SA` must be assessed against the full reach of the agent's tool set, not the process boundary.
2. **Scoring `PR` at the human's privilege.** Score the agent's effective credential.
3. **Scoring `UI:P` because a human is nominally in the loop.** If approval is routinely granted without meaningful review, `UI:N` is the honest value.
4. **Treating retrieval-sourced injection as requiring user interaction.** Content ingested autonomously is not user interaction.

### 4.2 Non-overlap rule

AI metrics MUST NOT rescore a condition already represented in CVSS. In particular: if model stochasticity was already encoded as `AT:P`, do **not** also score `SR`. Record which representation was used.

---

## 5. Part II — The AI metric group (normative)

Scored metrics: **LC**, **CP**, **AP**, **SR**. Supplemental: **TD**.

### 5.1 LC — Language-Mediated Control

Whether attacker-controlled natural language can influence security-relevant behaviour.

| Value | Label | Definition |
|---|---|---|
| `LC:D` | Direct | Attacker-supplied text reaches a privileged decision or tool-invocation path without mediation. |
| `LC:I` | Indirect | Attacker-controlled language enters through retrieved or ingested content and influences security-relevant behaviour. |
| `LC:M` | Mediated | Language influences behaviour only through a constrained interface: schema-bound arguments, allowlisted actions, or enforced human approval. |
| `LC:N` | None | No natural-language path to security-relevant behaviour. |

### 5.2 CP — Context Persistence

| Value | Label | Definition |
|---|---|---|
| `CP:C` | Cross-session | Persists in long-term memory, a vector store, or training data, and influences later sessions or other users. |
| `CP:S` | Session | Persists only within the active session. |
| `CP:N` | None | Single-turn only. |

### 5.3 AP — Agentic Propagation

| Value | Label | Definition |
|---|---|---|
| `AP:L` | Lateral | Compromised intent, instructions, memory, or authority crosses a trust boundary to other agents, tenants, or downstream systems. |
| `AP:C` | Contained | Propagates within the agent's own tool and action scope but does not cross a trust boundary. |
| `AP:N` | None | Confined to the initially affected component. |

### 5.4 SR — Stochastic Exploit Reliability

| Value | Label | Definition |
|---|---|---|
| `SR:R` | Reliable | Succeeds on essentially every attempt, or the attacker can retry freely until it succeeds. |
| `SR:P` | Probabilistic | Succeeds intermittently; retry is rate-limited, detectable, or otherwise constrained. |
| `SR:U` | Unreliable | Rarely reproducible, with no practical retry path. |

### 5.5 TD — Traceability Deficit (supplemental)

**TD never affects any numeric score.** It informs response priority, control requirements, and release gating.

| Value | Label | Definition |
|---|---|---|
| `TD:H` | High deficit | No reasoning trace and no tool-call audit; reconstruction infeasible. |
| `TD:M` | Moderate deficit | Partial logging; reconstruction possible with effort. |
| `TD:L` | Low deficit | Prompt, reasoning-trace, and tool-call logging retained and queryable. |

### 5.6 Vector syntax

AIVSS extends the CVSS v4.0 vector with an optional AI metric group, in the fixed order LC / CP / AP / SR / TD:

```
CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P/LC:D/CP:C/AP:L/SR:R/TD:H
```

All four scored metrics MUST be present together or all absent. TD is optional. An unknown key MUST cause a parse failure rather than a silent skip. A score MUST be rendered as `AIVSS:8.0`, never as a bare number.

---

## 6. AI Effect Class

The scored metrics produce an AI Effect Class by boolean ladder. No arithmetic is performed.

- **A2 (Substantial)** — `AP:L`, **or** (`LC ∈ {D, I}` **and** `CP:C`), **or** (`LC:D` **and** `SR:R`)
- **A1 (Present)** — not A2, and any scored metric above its benign value
- **A0 (None)** — `LC:N` and `CP:N` and `AP:N` and `SR:U`, or the AI metric group is absent

**A0 implies `AIVSS = CVSS-BTE` exactly, in both modes.** This is the Appendix E identity rule and it is verified exhaustively across all 270 MacroVectors by the reference implementation's `verify` command.

Rationale for the A2 clauses: propagation across a trust boundary is categorically the most severe agentic effect; persistent cross-session context poisoning reachable by language is the signature agentic attack pattern; and direct, reliable language control of a privileged path is a dependable injection primitive.

---

## 7. Part III — Decision track (normative at Level 2)

Severity does not determine remediation urgency. Since June 10, 2026, BOD 26-04 has replaced CVSS-severity-driven federal remediation with a four-variable model, and CISA publishes three of the four for every CVE ID through the Vulnrichment Program.

AIVSS consumes that model verbatim and adds one decision point.

| Decision point | Source |
|---|---|
| KEV Status | CISA KEV catalog |
| Automatable | CISA Vulnrichment; if unavailable, derive from `SR:R` |
| Technical Impact | CISA Vulnrichment; if unavailable, derive from CVSS `VC`/`VI`/`VA` |
| Asset Exposure | Assessing organization |
| **AI Effect Class** | AIVSS (§6) |

Where CISA has published neither Automatable nor Technical Impact and the CVE is not in KEV, BOD 26-04 directs that they be treated as "no" and "total" respectively. AIVSS follows that rule, applying the two derivations above only for findings that have no CVE and therefore no Vulnrichment record.

### 7.1 BOD 26-04 Table 1

All sixteen rows, transcribed from `cisa:BOD2604:1.0.0`. Held as a lookup table, not boolean logic: the fast tier requires exposure or automatability **in addition to** KEV, so the intuitive rule "KEV plus total impact means three days" is wrong for (KEV, not exposed, not automatable, total), which is 14 days.

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
| yes | yes | no | total | 3 days & forensic triage |
| yes | no | yes | total | 3 days & forensic triage |
| yes | yes | yes | total | 3 days & forensic triage |

### 7.2 Exploitation evidence ladder

Strict precedence, highest authority first. Replaces the withdrawn `max(ThM_discrete, ThM_EPSS, ThM_KEV)` construction, which allowed a categorical proxy to discard measured evidence and required an invented probability for non-CVE findings.

1. CVE listed in CISA KEV → **Active** (authoritative)
2. CISA Vulnrichment reports Exploitation: active → **Active** (authoritative)
3. Published EPSS → used **as published**, untransformed, **with its observation date** (mandatory: EPSS is revised daily and an undated score is not reproducible)
4. Exploitation observed and documented by the assessing organization → **Active (unverified)** — this is the rung for non-CVE agentic findings; it is explicitly *not* CISA-verified and MUST NOT be labelled KEV
5. Proof-of-concept exists → **PoC**
6. No evidence → **None**

There is no `EPSS_AI` and no `AI-KEV`. Both are withdrawn.

### 7.3 AI Effect Class escalation

When the AI Effect Class is **A2**, the recommended timeline advances by exactly one tier: `FSU → 60D → 14D → 3D`.

**Escalation stops at 3D.** AIVSS never escalates into forensic triage, because that obligation is a CISA determination tied to KEV listing and is not something a third-party framework may impose.

The unmodified BOD 26-04 result MUST always be reported alongside the AIVSS recommendation. For an FCEB agency the BOD value is the compliance obligation; the AIVSS value is a non-binding organizational overlay.

---

## 8. Scoring modes

### 8.1 Mode 1 — Interpretation (normative)

`AIVSS = CVSS-BTE`. AI metrics are reported as a profile. Immediately usable, zero score inflation, identity trivially preserved.

### 8.2 Mode 2 — MacroVector extension (provisional)

`AIVSS-BTEA = Lookup_AIVSS(EQ1..EQ6, A)`. See Annex A. **Provisional pending expert calibration; not for use in contracts, SLAs, or compliance gates.**

---

## 9. AIVSS-P — organizational priority index (Level 3, optional)

Organization-internal and non-portable.

```
AIVSS-P = 100 × geometric_mean(S/10, BI, REACH, L)
```

Each quantity is priced exactly once: `S` is technical severity, `BI` business criticality, `REACH` deployment reach, `L` organization-assessed likelihood. Exploitation appears nowhere — that belongs to the decision track. Controls appear nowhere — they belong to the CVSS environmental metrics or to the organization's own likelihood assessment.

Organizations should derive `L` with their existing methodology; NIST SP 800-30 Rev. 1 is a suitable reference.

### 9.1 What changed from the withdrawn Track P

The withdrawn Track P multiplied a Threat Multiplier term that was already inside its severity input, counted business criticality in two places and control strength in two more, and required sixteen OWASP Risk Rating factors per finding. Multiplying five sub-unit terms placed **88% of plausible inputs in the bottom band** — a Critical 9.5 with median context returned "Track."

### 9.2 Band calibration

Cut-points are the p90 / p65 / p35 quantiles of AIVSS-P over a uniform grid of severity 4.0–10.0 × business criticality × reach × likelihood (n = 10,980): **Immediate ≥ 78, This sprint ≥ 64, Scheduled ≥ 53, Backlog below 53.** Observed distribution: min 22, median 58, p95 83.

That grid over-represents high-severity findings relative to a real portfolio. Organizations SHOULD recalibrate against their own corpus before driving commitments from these bands.

---

## 10. Governance and calibration commitments

The working group commits to publishing, before v1.0:

1. **A conformance test-vector file** with exact expected outputs and zero tolerance.
2. **A score distribution** over a corpus of at least 200 assessed findings, published as a histogram. This is the only artifact that can genuinely test the severity-inflation charge.
3. **An inter-rater reliability study**: at least 20 findings × 8 assessors, with Krippendorff's α reported **per AI metric**. Low agreement on any metric is grounds for removing it.
4. **A change-control policy**: semantic versioning of the model, a public issue tracker, no silent formula changes, and a minimum 12-month deprecation notice.
5. **An expert-ranking exercise** to replace the Annex A strawman.

Incident back-testing is *not* promised for v1.0. The public agentic incident corpus is currently too thin to support it, and a thin back-test would be worse than none.

---

## 11. Intellectual lineage (non-normative)

AIVSS-P's likelihood × impact decomposition descends from the OWASP Risk Rating Methodology, and its separation of environmental context from intrinsic severity descends from CWSS v1.0. Both are cited as **design lineage, not current authority**: OWASP now recommends more mature alternatives for its Risk Rating Methodology, and CWSS was marked obsolete at v0.8 and has not been updated since 2018. AIVSS grounds its normative likelihood guidance in NIST SP 800-30 Rev. 1 accordingly.

---

## 12. Worked example

**Finding:** ASI06 Memory & Context Poisoning. Attacker-controlled text reaches a tool-invocation path directly, persists in the shared vector store across sessions, propagates to sibling agents, and reproduces reliably. No reasoning trace is retained.

```
CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P/LC:D/CP:C/AP:L/SR:R/TD:H
```

| Output | Value |
|---|---|
| MacroVector | `011110` |
| CVSS-BTE | **7.8** |
| AI Effect Class | **A2** (`AP:L`; also `LC:D`+`CP:C`; also `LC:D`+`SR:R`) |
| Mode 1 — AIVSS | **7.8** (normative) |
| Mode 2 — AIVSS-BTEA | **9.0** via promoted MacroVector `011010` (provisional) |
| Exploitation rung | PoC |
| Automatable | yes (derived from `SR:R`) |
| Technical Impact | total (derived from `VC:H`) |
| BOD 26-04 timeline | **3 days** |
| AIVSS recommendation | 3 days (already at ceiling; no escalation) |
| AIVSS-P (BI high, reach high, L 0.72) | **87 — Immediate** |

Every number above is emitted by the reference implementation, not computed by hand:

```bash
aivss-calc assess examples/asi06-memory-poisoning.json
```

---

## Annex A — MacroVector extension (provisional)

```
AIVSS-BTEA = Lookup_AIVSS(EQ1, EQ2, EQ3, EQ4, EQ5, EQ6, A)
```

`EQ1–EQ6` are the CVSS v4.0 equivalence groups (270 valid classes: 3 × 2 × 5 × 3 × 3, the EQ3/EQ6 pair being jointly constrained). `A` is the AI Effect Class.

### A.1 The S2 generator

A calibrated table requires an expert-ranking exercise that has not been performed. Until then, the table is generated by **equivalence-class promotion**: an AI Effect Class does not add a numeric uplift, it selects a neighbouring MacroVector and returns that MacroVector's existing CVSS score.

| Class | Promotion |
|---|---|
| A0 | none — identity |
| A1 | EQ4 → max(0, EQ4 − 1) |
| A2 | EQ4 → max(0, EQ4 − 1) and EQ1 → max(0, EQ1 − 1) |

EQ4 (`SC`/`SI`/`SA`) is promoted because subsequent-system impact is exactly the dimension that agentic persistence and propagation extend, and it is the metric group most commonly under-scored for agents. EQ1 (`AV`/`PR`/`UI`) is additionally promoted at A2 because substantial language-mediated control effectively removes privilege and interaction barriers.

**This generator invents no numbers.** Every AIVSS-BTEA value already exists in FIRST's expert-ranked `cvss_lookup.js`.

### A.2 Verified properties

Checked exhaustively across all 270 MacroVectors:

- **Identity:** `Lookup_AIVSS(EQ, A0) == CVSS-BTE` — 0 violations.
- **Monotone:** promotion never lowers a score — 0 violations. (The underlying table is monotone in EQ1–EQ5; EQ6 has no inversions, only the joint-constraint gaps.)
- **Closed:** every promoted MacroVector is a valid class. Promoting EQ1 or EQ4 can never violate the EQ3/EQ6 constraint, which is the second reason those two axes were chosen.
- **Bounded:** `AIVSS-BTEA ≤ 10.0`.
- **Ordered:** `A2 ≥ A1 ≥ A0` for every MacroVector.

### A.3 Known limitation

Promotion is coarse. A1 is a no-op for the 90 MacroVectors already at EQ4 = 0, and A2 is a full no-op for the 30 already at both EQ1 = 0 and EQ4 = 0 — 11% of the space. Saturation is reported explicitly in the tool output. Final values must come from expert ranking of representative vectors, not from any generator.

### A.4 Considered and rejected

A bounded-offset generator (A1 = +0.5, A2 = +1.0 at MacroVector level) offers finer granularity but reintroduces additive arithmetic on an ordinal input, which is the objection Annex A exists to avoid.

---

## Annex B — Withdrawn uplift model (informative)

**Deprecated. Scheduled for removal at v1.0.** Retained solely so organizations holding v0.8 scores can reproduce and migrate them.

```
AIVSS_S = CVSS_Base + (AARS × MF)          where AARS = (10 − CVSS_Base) × Factor_Mean × ThM
```

Two changes from v0.8:

1. **The mitigation factor applies to the uplift only.** Under v0.8, `MF = 0.67` could return a score *below* the CVSS base. The repaired form guarantees `CVSS_Base ≤ AIVSS_S ≤ 10.0`, verified exhaustively across CVSS 0.0–10.0 × Factor_Mean × ThM × MF.
2. **The category weight table is withdrawn.** Its values were asserted, never calibrated, and produced up to a 1.92× spread in the amplification term from the risk label alone. The factor mean is now unweighted.

The implementation reports `cvss_sensitivity` — the coefficient on `CVSS_Base` in the expanded form — so that the CVSS-signal attenuation described in §0 is visible rather than implicit.

Note for reviewers: the ThM Proof-of-Concept value of 0.97 corresponds to CVSS v3.1's *Functional* level; v3.1 assigns Proof-of-Concept 0.94 and Unproven 0.91. The v0.8 values are preserved unchanged here for reproducibility, not endorsed.

---

## References

- FIRST, *CVSS v4.0 Specification Document*, §8.2 MacroVectors — https://www.first.org/cvss/v4.0/specification-document
- FIRST, `cvss_lookup.js`, CVSS v4.0 calculator reference implementation (BSD-2-Clause)
- CISA, *BOD 26-04: Prioritizing Security Updates Based on Risk*, June 10, 2026
- CISA, *Reducing the Significant Risk of Known Exploited Vulnerabilities* (KEV criteria)
- CERT/CC, *SSVC: CISA BOD 26-04 Response Model* (`cisa:BOD2604:1.0.0`)
- OWASP GenAI Security Project, *Top 10 for Agentic Applications 2026* (ASI01–ASI10), December 9, 2025
- NIST SP 800-30 Rev. 1, *Guide for Conducting Risk Assessments*
- AIVSS v1.00.8 draft, Appendix E — *AIVSS v2 Proposal: CVSS-Compatible AI Scoring*
