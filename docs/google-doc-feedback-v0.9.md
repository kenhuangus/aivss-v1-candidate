# Google Doc Feedback — AIVSS v1.00.8 → v0.9

Target document: [AIVSS Scoring System draft](https://docs.google.com/document/d/1SIO6yN1x4XXTnclLeEsFFHnqzRR-3SOvUJTHF7CGRpI/edit)

Supporting material: [AIVSS v0.9 Specification](AIVSS-v0.9-Specification.md) · [Appendix E, Completed](appendix-e-completed.md)

This supersedes an earlier round of feedback that proposed repairing the uplift formula in place. Analysis of the repaired formula showed the repair was necessary but not sufficient, so the recommendation changed. The findings driving that change are in Comments 1–3.

---

## Comment 1 — The EPSS integration is inert, and §3.4's own example demonstrates it

**Anchor:** Table 4a, Threat Multiplier values

**Finding.** `ThM_discrete` for Proof-of-Concept is 0.97 and is the documented default. `ThM_EPSS = 0.50 + 0.50 × EPSS`. Under `max()` selection, the EPSS term can therefore only change the result when **EPSS > 0.94** — a small fraction of the published EPSS distribution, most of which is already KEV-listed and pinned to 1.00 anyway.

Measured maximum effect of the entire EPSS dimension on a score: **0.1 points.** The draft's own worked example shows EPSS 0.42 producing `ThM_EPSS = 0.71`, which is discarded.

`EPSS_AI` is worse: four booleans at 0.25 each yield five reachable values, so under the PoC default it can only alter the score when all four fire — and one of those signals ("active abuse telemetry") independently implies Attacked.

**Recommendation.** Replace `max()` with a strict evidence-precedence ladder in which measured evidence is never discarded in favour of a categorical proxy. See Comment 4.

---

## Comment 2 — The CVSS base is attenuated to near-irrelevance at expected factor levels

**Anchor:** §3.4 AIVSS formula

**Finding.** Expanding gives `AIVSS_S = (1 − k)·CVSS_Base + 10k` where `k = Factor_Sum × ThM × MF`. At the draft's own worked-example factor level (0.85, ThM 0.97, MF 1.0) the coefficient on `CVSS_Base` is **0.1755**: a CVSS 0.1 finding scores 8.3 and a CVSS 9.9 finding scores 10.0. A 9.8-point spread compresses to 1.7 points. At Factor_Sum 0.9 every CVSS ≥ 2.13 is Critical; at 1.0 everything is Critical. Over a uniform grid, 33% comes out Critical.

This is Appendix E's "severity inflation without recalibrating the full scoring model", demonstrated numerically, and it undermines the claim that the CVSS base is the technical floor. It is a floor, but it is also nearly the only part of the score that doesn't matter.

**Recommendation.** This is not repairable by adjusting constants. See Comment 3.

---

## Comment 3 — Adopt Appendix E Option 3 as the architecture, not as a deferred Phase 2

**Anchor:** Appendix E, and the framing of the uplift model as the primary path

**Finding.** Appendix E raises a *correctness* objection: the uplift construction "is the least defensible mathematically." Sequencing it as Phase 1 answers a correctness objection with a schedule. It does not resolve it, and the resolution will resurface during any large adopter's due diligence.

Comments 1 and 2 independently confirm two of Appendix E's three charges.

**Recommendation.** Restructure around Option 3 now:

- **Part I — Interpretation guide.** `AIVSS = CVSS-BTE`. Normative. Requires the factor→CVSS mapping table that Appendix E §2 mandates but never supplies; a complete version is in [appendix-e-completed.md](appendix-e-completed.md) §2.
- **Part II — AI metric group.** LC / CP / AP / SR / TD with full value levels and a boolean AI Effect Class ladder. Appendix E §§3–4 name these and define neither.
- **Part III — Decision track.** CISA BOD 26-04. See Comment 4.
- **Annex A — MacroVector extension.** Provisional, with a documented generator.
- **Annex B — Uplift model.** Informative only, deprecated at v1.0, retained for v0.8 migration.

Reproduce Appendix E verbatim rather than paraphrasing it into a roadmap bullet. The current §1.1 framing converts a named reviewer's objection into a neutral roadmap item, which is discoverable by anyone who reads the original and is more damaging than the objection itself.

---

## Comment 4 — Leverage KEV through BOD 26-04, not as a multiplier term

**Anchor:** §3.4 Threat Multiplier, and any section treating KEV as a scoring input

**Finding.** CISA revoked BOD 22-01 and BOD 19-02 on **June 10, 2026** and replaced CVSS-severity-driven remediation with **BOD 26-04**, a four-variable model: Asset Exposure × KEV Status × Automatable × Technical Impact. CISA publishes three of the four for every CVE ID through Vulnrichment. Table 1 maps the sixteen combinations to mandatory timelines.

Treating KEV as a `1.00` term inside a multiplier discards all of this.

**Recommendation.** Consume BOD 26-04 verbatim and add the AI Effect Class as a fifth decision point, escalating one tier at A2 and stopping short of forensic triage (that obligation is CISA's determination to make). Always report the unmodified BOD result alongside, so an FCEB agency cannot mistake an AIVSS overlay for its compliance obligation.

Note the trap in transcribing Table 1: the fast tier requires exposure **or** automatability in addition to KEV, so "KEV plus total impact means three days" is wrong for (KEV, not exposed, not automatable, total), which is 14 days. Encode it as a 16-row lookup, not boolean conditions.

**Exploitation evidence ladder**, replacing `max(ThM_discrete, ThM_EPSS, ThM_KEV)`:

1. CISA KEV → Active (authoritative)
2. Vulnrichment `Exploitation: active` → Active (authoritative)
3. Published EPSS → used as published, untransformed, **with observation date**
4. Organization-observed exploitation → Active (unverified) — the rung for non-CVE agentic findings
5. PoC → PoC
6. None

---

## Comment 5 — Withdraw `EPSS_AI`, `AI-KEV`, and `SSVC-AI`

**Anchor:** §3.4 and the decision-track section

**Finding.** Each borrows an owning organization's name for an artifact that lacks the property the name asserts.

| Term | Problem |
|---|---|
| `EPSS_AI` | EPSS is a trained model over ~1,500 features producing a calibrated 30-day probability with published performance curves. This is four booleans. Given the CVSS FAQ criticism already on record, this is the most quotable mistake in the document. |
| `AI-KEV` | KEV's defining property is *government-verified* exploitation carrying a BOD deadline. The draft assigns AI-KEV and CISA KEV the identical value of 1.00, asserting evidentiary equivalence with a federal verification process. |
| `SSVC-AI` | SSVC is CMU/SEI CERT's and is a decision *tree* over categorical inputs. The draft's version is a threshold rule over a numeric score. |

**Recommendation.** Delete all three. Under the Comment 4 architecture none is needed: KEV is consumed directly from CISA, EPSS is used as published, and the decision points are cited from CERT-CC by reference — which is what BOD 26-04 itself does.

---

## Comment 6 — The decision procedure emits only two of its three outcomes

**Anchor:** Decision-track rules

**Finding.** The Attend rule fires on `AIVSS-S ≥ 4.0` **OR** (`ThM_discrete ≥ 0.97` AND `Tools ≥ 0.5`). Since 0.97 is the default and every agentic finding by definition has tool access, the second clause is almost always true. **"Track" is unreachable for every score from 0.0 to 10.0.** A three-outcome procedure that emits two has no decision value.

**Recommendation.** Replaced entirely by BOD 26-04's five tiers under Comment 4. Whatever is adopted, publish the outcome distribution over a corpus — a procedure that never emits one of its outcomes should be caught by the project's own calibration data.

---

## Comment 7 — Adopt ASI01–ASI10 as the canonical taxonomy

**Anchor:** The bespoke ten-category risk list

**Finding.** Appendix E §1 already directs AIVSS to "use the existing OWASP Agentic AI / LLM Top 10 as the canonical risk taxonomy." The bespoke list also has two structural defects: it splits access-control violation and identity impersonation into separate categories that both map to ASI03, and it has no equivalent for **ASI09 Human–Agent Trust Exploitation** or **ASI10 Rogue Agents**.

**Recommendation.** Adopt **OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)**, published December 9, 2025. A crosswalk from the withdrawn categories is implemented in the reference tool. Note that "Agent Untraceability" has no ASI successor by design — traceability is a property of the deployment, not a risk class, and is carried as the supplemental `TD` metric.

---

## Comment 8 — Publish the Risk Amplification Matrix, or withdraw the weights

**Anchor:** The `w_i(c)` weighting reference

**Finding.** The draft normatively references weights from a Risk Amplification Matrix that is never published. The draft's own text elsewhere says such weights *may* be used in future versions once "calibrated through incident analysis, red-team results, and inter-rater reliability testing." That calibration has not occurred, yet the weights are in use.

They also break cross-category comparability: identical technical facts produce a **1.92× spread** in the amplification term depending only on the category label.

**Recommendation.** Withdraw them. A specification whose normative constants are recoverable only by reading a reference implementation is not a specification.

---

## Comment 9 — Add a scope-and-non-goals section

**Anchor:** Front matter

**Finding.** The CVSS SIG's specific objection is that AIVSS "merges software quality, ethics, privacy, and cybersecurity issues into one-size-fits-all risk measurement" and its specific recommendation is that these be "kept separate." The draft never states a scope boundary, so the objection stands unanswered.

**Recommendation.** State plainly that AIVSS scores the security consequences of vulnerabilities in deployed agentic systems, and does **not** score model alignment, jailbreak resistance, content safety, bias, or fairness — and that the working group agrees these should not be combined with cybersecurity scoring. This is the cheapest and most direct available response, and it also keeps AIVSS out of a lane where a competing industry effort has structural advantages in data access.

---

## Comment 10 — Add a provenance table and a non-claims list

**Anchor:** Front matter

**Recommendation.** Classify every constant as **derived**, **asserted**, or **calibrated**. In the current draft, nothing is calibrated, and saying so plainly is far stronger than being caught.

Add explicitly that AIVSS does not claim: comparability with or endorsement by CVSS/FIRST; integration with or endorsement by FIRST, CISA, or CERT/CC; probability or expected-loss semantics; interval-scale arithmetic; empirical validation; or standalone remediation-mandate authority.

One more, for §1.3: "decimal precision reflects calculation rigor, not interval-scale impact" does not mean anything defensible — decimal precision reflects arithmetic, not rigor. And the caveat is contradicted two pages later when ordinal 0–9 factors are averaged and multiplied. Resolve the contradiction rather than restating the caveat.

---

## Verification

Every numeric finding above is reproducible:

```bash
cd tools/aivss-calc && pip install -e ".[dev]"
aivss-calc verify                                  # identity rule, 270 MacroVectors, 0 violations
aivss-calc assess examples/asi06-memory-poisoning.json
pytest                                             # 88 tests, exact assertions
```
