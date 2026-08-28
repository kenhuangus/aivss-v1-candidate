# aivss-calc

Reference implementation of [AIVSS v1.0 — CVSS-Compatible AI Scoring](../../docs/AIVSS-1.0-Google-Doc.md).

AIVSS never invents a score. In interpretation mode the number it emits *is* a CVSS v4.0 score; in MacroVector extension mode it applies ceiling-delta promotion on the interpolated CVSS-BTE score. Prioritization is handled separately, by CISA BOD 26-04.

## Install

```bash
cd tools/aivss-calc
pip install -e ".[dev]"
```

## Commands

### `verify` — check the Appendix E identity rule

```bash
aivss-calc verify
```

```json
{
  "macrovectors": 270,
  "identity_rule_violations": 0,
  "identity_rule_holds": true,
  "monotonicity_violations": 0,
  "saturated_no_op": { "A1": 90, "A2": 30 }
}
```

### `profile` — Mode 1 (normative)

`AIVSS = CVSS-BTE`; AI metrics are reported as a profile and do not modify the score.

```bash
aivss-calc profile "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P/LC:D/CP:C/AP:L/SR:R/TD:H"
```

### `lookup` — Mode 2 (provisional)

`AIVSS-BTEA = min(10.0, CVSS-BTE + (Lookup_AIVSS(promoted_MV, A) − Lookup_AIVSS(base_MV, A0)))` via S2 equivalence-class promotion.

```bash
aivss-calc lookup "CVSS:4.0/.../E:P/LC:D/CP:C/AP:L/SR:R/TD:H"
```

### `decide` — CISA BOD 26-04 remediation timeline

Reports the unmodified BOD 26-04 result alongside the AIVSS recommendation. For FCEB agencies the BOD value is the compliance obligation; the AIVSS value is a non-binding overlay.

```bash
aivss-calc decide --vector "<vector with AI group>" --publicly-exposed --kev --technical-impact total
```

### `assess` — full report

```bash
aivss-calc assess examples/asi06-memory-poisoning.json
```

Output validates against [`schemas/aivss-report-v1.0.json`](../../schemas/aivss-report-v1.0.json).

### `priority` — Level 3 organizational index

Organization-internal; not comparable across organizations.

```bash
aivss-calc priority --severity 8.0 --business-criticality high --reach high --likelihood 0.72
```

### `legacy` — Annex B, withdrawn uplift model

Deprecated, informative only. Retained so v0.8 scores can be reproduced and migrated.

```bash
aivss-calc legacy --factors <file>
```

### `taxonomy` — OWASP Top 10 for Agentic Applications 2026

```bash
aivss-calc taxonomy
```

## AI metrics

| Metric | Values (most severe first) |
|---|---|
| `LC` Language-Mediated Control | `D` Direct · `I` Indirect · `M` Mediated · `N` None |
| `CP` Context Persistence | `C` Cross-session · `S` Session · `N` None |
| `AP` Agentic Propagation | `L` Lateral · `C` Contained · `N` None |
| `SR` Stochastic Exploit Reliability | `R` Reliable · `P` Probabilistic · `U` Unreliable |
| `TD` Traceability Deficit (mandatory) | `H` High · `M` Moderate · `L` Low |

**TD** is mandatory in every conformant assessment (Section 7). When scored metrics (LC/CP/AP/SR) are present, TD must appear in the same vector fragment.

AI Effect Class is a boolean ladder, never arithmetic:

- **A2** — `AP:L`, or (`LC ∈ {D,I}` and `CP:C`), or (`LC:D` and `SR:R`)
- **A1** — not A2, and any scored metric above its benign value
- **A0** — all benign, or only TD is present → `AIVSS = CVSS-BTE` exactly

## Tests

```bash
pytest
```

95 tests with exact assertions and no tolerances, including exhaustive verification of the identity rule, promotion monotonicity, the Annex B floor guarantee, and all sixteen BOD 26-04 Table 1 rows.

## Attribution

`aivss_calc/data/cvss_v4_lookup.json` is derived from `cvss_lookup.js` in the FIRST CVSS v4.0 calculator reference implementation. Copyright FIRST, Red Hat, and contributors; BSD-2-Clause. AIVSS is not affiliated with, endorsed by, or in collaboration with FIRST or the CVSS SIG.
