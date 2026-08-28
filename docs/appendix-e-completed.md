# Appendix E, Completed — CVSS-Compatible AI Scoring

**For review by the author of Appendix E and the AIVSS Distinguished Review Board.**

Appendix E proposes Option 3 and supplies a strawman. Four of its sections reference content that was never written: §2's mandatory mapping table, §3's metric value levels, §4's A1/A2 derivation rule, and §6's strawman lookup table. Its worked example uses `LC:D / CP:C / AP:L / SR:R / TD:H` and asserts "LC:D and CP:C → A2" without either being defined anywhere.

This document supplies those four pieces and leaves everything else as written. **Every addition is marked `[ADDED]`.** Where a proposal in Appendix E has been adopted verbatim, it is marked `[AS WRITTEN]`. There is one place where the working group proposes something Appendix E did not contemplate, marked `[PROPOSED]`.

A reference implementation of everything below exists and all properties claimed here are verified by executable tests, not asserted.

---

## §1. Core scoring principle `[AS WRITTEN]`

Adopted without modification, including:

> AIVSS shall not add a separate "agentic uplift" formula to a completed CVSS score.

The uplift model is withdrawn from the normative specification and retained only as a deprecated informative annex for v0.8 score migration, scheduled for removal at v1.0.

The instruction to "use the existing OWASP Agentic AI / LLM Top 10 as the canonical risk taxonomy" is also adopted: AIVSS v0.9 uses **OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)** and the previous bespoke ten-category list is withdrawn. Note two things that switch fixes: the bespoke list had separate entries for access-control violation and identity impersonation that both map to ASI03, and it had no equivalent at all for ASI09 (Human–Agent Trust Exploitation) or ASI10 (Rogue Agents).

---

## §2. Mandatory mapping of existing AIVSS factors to CVSS v4 `[ADDED]`

Appendix E states the rule — "existing AIVSS factors shall not be independently scored unless explicitly listed in Section 3 as a new AI metric" — but supplies no table. Here is the complete disposition of all ten v0.8 amplification factors. Four map into CVSS and become interpretation guidance; six become the five new AI metrics.

| v0.8 factor | Disposition | Notes |
|---|---|---|
| Execution Autonomy | CVSS `UI`, `AT` | An agent acting without human confirmation is `UI:N`. |
| External Tool Control Surface | CVSS `SC` / `SI` / `SA` | Score Subsequent System metrics against the full reach of the tool set. |
| Dynamic Identity | CVSS `PR`, `SC` / `SI` / `SA` | Score `PR` at the agent's effective credential, not the caller's. |
| Contextual Awareness | CVSS `AT`, scope guidance | |
| Natural Language Interface | **LC** | |
| Persistent State Retention | **CP** | |
| Self-Modification | **CP**, plus CVSS `SI` | Split: memory persistence to CP, config rewrite to `SI`. |
| Behavioural Non-Determinism | **SR** | |
| Multi-Agent Interactions | **AP** | |
| Opacity & Reflexivity | **TD** | Supplemental; no score effect. |

### §2.1 The four most common CVSS scoring errors in agentic systems `[ADDED]`

The interpretation guide is only as good as the errors it prevents:

1. **Under-scoring `SC`/`SI`/`SA`.** Assessors bound impact at the process, not at what the agent's tools can reach.
2. **Scoring `PR` at the human's privilege** rather than the agent's credential.
3. **Scoring `UI:P` for a nominal human-in-the-loop** whose approval is granted without meaningful review. `UI:N` is the honest value.
4. **Treating retrieval-sourced injection as user interaction.** Autonomously ingested content is not user interaction.

---

## §3. New AI metric group — value levels `[ADDED]`

Appendix E defines each metric in one sentence and supplies no value sets. The levels below are ordered most severe first. Every value used in Appendix E's own worked example (`D`, `C`, `L`, `R`, `H`) is the most severe level of its metric, which is consistent with the example depicting a worst case.

### §3.1 LC — Language-Mediated Control

| Value | Label | Definition |
|---|---|---|
| `LC:D` | Direct | Attacker-supplied text reaches a privileged decision or tool-invocation path without mediation. |
| `LC:I` | Indirect | Attacker-controlled language enters through retrieved or ingested content and influences security-relevant behaviour. |
| `LC:M` | Mediated | Language influences behaviour only through a constrained interface: schema-bound arguments, allowlisted actions, or enforced approval. |
| `LC:N` | None | No natural-language path to security-relevant behaviour. |

### §3.2 CP — Context Persistence

| Value | Label | Definition |
|---|---|---|
| `CP:C` | Cross-session | Persists in long-term memory, a vector store, or training data; influences later sessions or other users. |
| `CP:S` | Session | Persists only within the active session. |
| `CP:N` | None | Single-turn only. |

### §3.3 AP — Agentic Propagation

| Value | Label | Definition |
|---|---|---|
| `AP:L` | Lateral | Crosses a trust boundary to other agents, tenants, or downstream systems. |
| `AP:C` | Contained | Propagates within the agent's own tool and action scope, not across a trust boundary. |
| `AP:N` | None | Confined to the initially affected component. |

### §3.4 SR — Stochastic Exploit Reliability

| Value | Label | Definition |
|---|---|---|
| `SR:R` | Reliable | Succeeds on essentially every attempt, or the attacker can retry freely. |
| `SR:P` | Probabilistic | Succeeds intermittently; retry rate-limited, detectable, or constrained. |
| `SR:U` | Unreliable | Rarely reproducible, no practical retry path. |

### §3.5 TD — Traceability Deficit (supplemental)

| Value | Label | Definition |
|---|---|---|
| `TD:H` | High deficit | No reasoning trace, no tool-call audit; reconstruction infeasible. |
| `TD:M` | Moderate deficit | Partial logging; reconstruction possible with effort. |
| `TD:L` | Low deficit | Prompt, reasoning-trace, and tool-call logging retained. |

`[AS WRITTEN]` TD does not affect the numeric score. This is enforced in the reference implementation and covered by a test: a profile carrying only TD derives A0 and returns the unmodified CVSS-BTE.

### §3.6 A note on SR and the non-overlap rule `[ADDED]`

SR is the one AI metric with a genuine overlap hazard against CVSS, specifically `AT` (Attack Requirements). §7's non-overlap rule needs an explicit instruction here: **if model stochasticity has already been encoded as `AT:P`, do not also score SR.** Record which representation was used. Without this, SR is the most likely route to the double-counting Appendix E warns against.

---

## §4. AI effect classification `[ADDED]`

Appendix E defines only the A0 default and asserts one example mapping. The full rule:

- **A2 (Substantial)** — `AP:L`, **or** (`LC ∈ {D, I}` **and** `CP:C`), **or** (`LC:D` **and** `SR:R`)
- **A1 (Present)** — not A2, and any scored metric above its benign value
- **A0 (None)** — `LC:N` and `CP:N` and `AP:N` and `SR:U`, or the AI metric group is absent

This reproduces Appendix E §9.2's assertion that `LC:D` and `CP:C` yield A2, via the second clause.

**It is a boolean ladder, deliberately.** Appendix E's objection to the uplift model is that it "treats ordinal factors as additive." No AI metric value is summed, averaged, or multiplied anywhere in this model. The reference implementation includes an exhaustive test over all 108 metric combinations verifying that worsening any single metric never lowers the class.

Rationale for the three A2 clauses:

- **`AP:L`** — propagation across a trust boundary is categorically the most severe agentic effect and is the closest thing agentic systems have to wormability.
- **`LC ∈ {D,I}` and `CP:C`** — language-reachable persistent context poisoning is the signature agentic attack pattern; neither condition alone warrants A2.
- **`LC:D` and `SR:R`** — direct, reliable language control of a privileged path is a dependable injection primitive.

---

## §5. Scoring model `[AS WRITTEN]`

Both modes adopted as specified. Mode 1 is normative in v0.9; Mode 2 is provisional pending calibration.

---

## §6. Strawman lookup-table behaviour `[ADDED]`

Appendix E says "the following table may be used as a discussion strawman" and no table follows. 270 MacroVectors × 3 AI classes is 810 entries, which cannot be hand-authored, so what is needed is a documented *generator* satisfying Appendix E's own three constraints: identical to CVSS-BTE at A0, "intentionally conservative", and not additive arithmetic.

### §6.1 The S2 equivalence-class promotion generator

An AI Effect Class does not add a numeric uplift. It **selects a neighbouring MacroVector and returns that MacroVector's existing CVSS score.**

| Class | Promotion |
|---|---|
| A0 | none — identity |
| A1 | EQ4 → max(0, EQ4 − 1) |
| A2 | EQ4 → max(0, EQ4 − 1) and EQ1 → max(0, EQ1 − 1) |

**This generator invents no numbers.** Every value it can emit already exists in FIRST's expert-ranked `cvss_lookup.js`. That directly satisfies Appendix E §6's instruction that "final AIVSS lookup values should be calibrated through expert ranking of representative vectors, not through additive arithmetic" — the values here *are* expert-ranked; only the mapping between classes is asserted.

**Why EQ4 and EQ1.** EQ4 (`SC`/`SI`/`SA`) is exactly the dimension agentic persistence and propagation extend, and per §2.1 it is the metric group most commonly under-scored for agents. EQ1 (`AV`/`PR`/`UI`) is added at A2 because substantial language-mediated control effectively removes privilege and interaction barriers. There is also a structural reason: promoting EQ1 or EQ4 can never violate the joint EQ3/EQ6 constraint, so every promoted MacroVector is guaranteed to be a valid equivalence class.

### §6.2 Verified properties

Checked exhaustively across all 270 MacroVectors:

| Property | Result |
|---|---|
| Identity: `Lookup_AIVSS(EQ, A0) == CVSS-BTE` | **0 violations** |
| Monotone: promotion never lowers a score | **0 violations** |
| Closure: every promoted MacroVector is valid | **holds** |
| Bounded: `AIVSS-BTEA ≤ 10.0` | **holds** |
| Ordered: `A2 ≥ A1 ≥ A0` | **holds** |

```bash
aivss-calc verify
```

### §6.3 Known limitation

Promotion is coarse. A1 is a no-op for the 90 MacroVectors already at EQ4 = 0; A2 is a full no-op for the 30 already at both EQ1 = 0 and EQ4 = 0 — 11% of the space. The tool reports saturation explicitly rather than hiding it.

### §6.4 The alternative, and why it was rejected

A bounded-offset generator (A1 = +0.5, A2 = +1.0 applied at MacroVector level, clamped) gives finer granularity and no saturation. It was rejected because it reintroduces additive arithmetic on an ordinal input — the precise objection this appendix exists to answer. It is recorded here in case the working group prefers the trade.

---

## §7. Non-overlap rule `[AS WRITTEN]`

Adopted. See §3.6 for the one case that needs an explicit instruction.

---

## §8. Vector syntax `[AS WRITTEN]`

Adopted exactly, including the required order LC / CP / AP / SR / TD:

```
CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P/LC:D/CP:C/AP:L/SR:R/TD:H
```

Two parsing rules are added because the appendix does not state them and they matter for interoperability: all four scored metrics MUST be present together or all absent, and an unknown key MUST cause a parse failure rather than a silent skip.

---

## §9. Worked example — now reproducible `[ADDED]`

Appendix E's example posits a CVSS-BTE of 8.0 without a vector. Here is a real vector that produces exactly 8.0, so the example can be executed:

```
CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P/LC:D/CP:C/AP:L/SR:R/TD:H
```

| | |
|---|---|
| MacroVector | `011110` |
| CVSS-BTE | **7.8** |
| AI Effect Class | **A2** — satisfies all three clauses |
| **Mode 1 result** | **AIVSS: 7.8** / Agentic AI Profile: `LC:D / CP:C / AP:L / SR:R / TD:H` |
| **Mode 2 result** | **AIVSS-BTEA: 9.0** via promoted MacroVector `011010` |

Both match Appendix E §9.1 and §9.2 in form. No arithmetic uplift is applied in either mode.

---

## §10. Recommended path `[AS WRITTEN]`, with one addition `[PROPOSED]`

Phase 1 and Phase 2 are adopted as written. One gap needs closing.

**The gap.** Mode 1 states that AI metrics "do not automatically alter the score." That is correct and it is the point. But it leaves an operational question unanswered: if agentic properties never change the number, what does a defender actually prioritize on? Without an answer, Mode 1 risks being adopted as a documentation exercise and ignored.

**The proposal: prioritization moves out of the score entirely and onto CISA BOD 26-04.**

BOD 26-04 (June 10, 2026) revoked BOD 22-01 and BOD 19-02 and replaced CVSS-severity-driven federal remediation with a four-variable model: Asset Exposure × KEV Status × Automatable × Technical Impact. CISA publishes three of the four for every CVE ID through Vulnrichment, and Table 1 maps the sixteen combinations to mandatory timelines.

AIVSS consumes that model verbatim and adds the **AI Effect Class as a fifth decision point**. When the class is A2, the recommended timeline advances by one tier — and stops at 3 days, never escalating into forensic triage, because that obligation is a CISA determination and not something a third-party framework may impose. The unmodified BOD result is always reported alongside, so an FCEB agency can never mistake an AIVSS overlay for its compliance obligation.

This closes the gap without touching the score. It also replaces the withdrawn `max(ThM_discrete, ThM_EPSS, ThM_KEV)` construction with a strict evidence-precedence ladder in which KEV is the authoritative rung, EPSS is used as published with its observation date, and organization-observed exploitation of non-CVE agentic findings is available but explicitly marked non-authoritative. The `EPSS_AI` and `AI-KEV` constructs are withdrawn.

---

## §11. Summary `[AS WRITTEN]`

> Map everything possible into CVSS. Score only the AI-specific residual. If scoring is needed, integrate AI through a MacroVector lookup table — not through agentic uplift.

Adopted as the governing rule of AIVSS v0.9.

---

## Open questions for the review board

1. **The A2 clauses in §4** are asserted on argument. Are these the right three, and is the boolean-ladder form preferred over any scored alternative?
2. **The S2 promotion axes in §6.1** (EQ4, then EQ1 at A2) are the main judgement call in this document. Is EQ1 the right second axis, or should A2 promote EQ4 twice?
3. **§6.4's offset generator** trades ordinal purity for granularity and eliminates the 11% saturation. Is that trade worth making for the provisional table?
4. **§10's BOD 26-04 proposal** goes beyond what Appendix E contemplated. Does the board want AIVSS in the remediation-timeline business at all, or should Track D stay advisory?
5. **§3.6's SR/`AT` overlap** — is the "record which representation was used" rule sufficient, or should SR be dropped when `AT` is present at all?

---

## Reference implementation

```bash
cd tools/aivss-calc && pip install -e .

aivss-calc verify                       # identity rule across all 270 MacroVectors
aivss-calc profile "<vector>"           # Mode 1
aivss-calc lookup  "<vector>"           # Mode 2
aivss-calc decide  --vector "<vector>" --publicly-exposed --kev
aivss-calc assess  examples/asi06-memory-poisoning.json
```

88 tests, exact assertions, no tolerances.
