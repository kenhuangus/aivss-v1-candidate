# AIVSS v1.0 Candidate Calculator

Reference implementation of **AIVSS** — CVSS-compatible risk scoring for **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10).

## Scoring summary

| Output | Formula |
|--------|---------|
| **AIVSS** (Mode 1) | `min(10, CVSS-BTE + TD_delta)` |
| **AI Effect Class** | Boolean ladder on LC / CP / AP / SR |
| **AIVSS-BTEA** (Mode 2) | MacroVector ceiling-delta + TD_delta |
| **AIVSS-P** | Geometric mean using TD-adjusted severity |

**TD (Traceability Deficit)** is mandatory and adjusts risk: `TD:H +0.5`, `TD:M +0.2`, `TD:L +0.0`. See [`docs/SCORING.md`](docs/SCORING.md).

## Install

```bash
pip install -e ".[dev]"
pytest
```

## CLI

```bash
aivss-calc assess examples/asi06-example.json
aivss-calc profile "CVSS:4.0/.../LC:D/CP:C/AP:L/SR:R/TD:H"
aivss-calc taxonomy
aivss-calc verify
```

## Examples

One worked finding per ASI category in [`examples/`](examples/). Regenerate with:

```bash
python examples/generate_asi_examples.py
```

## Schema

Assessment JSON validates against [`schemas/aivss-report-v1.0.json`](schemas/aivss-report-v1.0.json).

## Attribution

`aivss_calc/data/cvss_v4_lookup.json` is derived from FIRST CVSS v4.0 `cvss_lookup.js` (BSD-2-Clause). AIVSS is not affiliated with FIRST or the CVSS SIG.
