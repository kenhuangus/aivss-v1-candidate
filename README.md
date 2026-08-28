# AIVSS v1.0 Candidate Calculator

Reference implementation of **AIVSS** — CVSS-compatible risk scoring for **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10).

Read [`docs/SCORING.md`](docs/SCORING.md) first — it defines **Agentic AI Profile**, **Agentic Effect Class** (A0/A1/A2), and every scoring formula. See [`docs/CVSS-MAPPING.md`](docs/CVSS-MAPPING.md) for what CVSS covers vs what AIVSS adds.

## Scoring summary

| Output | Formula |
|--------|---------|
| **AIVSS** (Mode 1) | `min(10, CVSS-BTE + EX_delta + TD_delta)` |
| **Agentic Effect Class** | Boolean ladder on LC / CP / AP / SR / EX (A0 absent → A2 substantial) |
| **AIVSS-BTEA** (Mode 2) | MacroVector ceiling-delta + EX_delta + TD_delta |
| **AIVSS-P** | Geometric mean using EX- and TD-adjusted severity |

**EX (Extension Surface)** and **TD (Traceability Deficit)** are mandatory risk factors:

| Metric | Values | Risk delta |
|--------|--------|------------|
| EX | W / M / N | +0.4 / +0.15 / +0.0 |
| TD | H / M / L | +0.5 / +0.2 / +0.0 |

## Install

```bash
pip install -e ".[dev]"
pytest
```

## CLI

```bash
aivss-calc assess examples/asi06-example.json
aivss-calc profile "CVSS:4.0/.../LC:D/CP:C/AP:L/SR:R/EX:W/TD:H"
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
