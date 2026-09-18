# AIVSS 1.0

## 🌐 Try it online

Two live resources are hosted for this project — no installation needed:

1. **Interactive Web Calculator** — score an agentic AI vulnerability in your
   browser. Pick the CVSS v4.0 and Agentic AI metrics or start from one of the
   ten OWASP Agentic Top 10 examples, and get the CVSS-BTE severity, Effect
   Class, and optional SSVC / CISA BOD 26-04 remediation timeline instantly.
   It runs the exact same reference code as the CLI.
   **→ https://kenhuangus.github.io/aivss-v1-candidate/**

2. **Interactive Slide Deck** — a 23-slide masterclass presentation covering
   the AIVSS 1.0 decoupled architecture, CVSS v4.0 interpretation, the
   eight-metric Agentic AI profile, SSVC / BOD 26-04 timelines, and the
   EchoLeak (`CVE-2025-32711`) case study. Use arrow keys to navigate.
   **→ https://kenhuangus.github.io/aivss-v1-candidate/slides.html**

AIVSS is a candidate extension profile for describing vulnerabilities in
Agentic AI systems. It keeps the official CVSS v4.0 vector and score intact and
records eight Agentic AI metrics in a separate extension vector.

Status: **candidate**. The metric rubric and conformance rules are testable.
The remediation overlay and organization-local priority index are **not
empirically calibrated** and must not be presented as standards, probabilities,
or regulatory requirements.
The [extension manifest](aivss-extension.json) records
`first_validation_status: not-submitted`; FIRST has not validated or endorsed
this candidate.

## Model

- **Normative severity:** `AIVSS = CVSS-BTE` — agentic metrics are parallel metadata
- Classifying metrics: **LC, CP, AP, SR**
- Assurance metrics: **EX, PT, CA, TD** (Traceability Deficit)
- Unknown evidence value: **X**
- Effect classes: **A0, A1, A2, AX**
- **Level 1:** requires `cvss_vector` + complete `aivss_vector` (eight metrics)
- **Exploit Maturity (`E`):** resolved from the evidence ladder before CVSS-BTE scoring
- **Taxonomy:** ASI01–ASI10, or `MAESTRO-EXTENDED` with layer/threat metadata

Layer 3 remediation uses CERT/CC SSVC decision table **`cisa:DT_BOD2604:1.0.0`**
(BOD 26-04), with Agentic AI Effect Class **A2** as a fifth transparent extension
input. See [docs/SSVC.md](docs/SSVC.md).

Level 1 assessments always supply all eight Agentic AI Profile metrics plus a
rationale for each. `AX` is used when classifying evidence is insufficient
(`X` on LC/CP/AP/SR). Findings outside ASI01–ASI10 are recorded as
`MAESTRO-EXTENDED` with required taxonomy metadata (Section 5.7).

CVSS and AIVSS vectors are separate, following the
[CVSS v4.0 Extensions Framework](https://www.first.org/cvss/v4.0/user-guide):

```text
CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P
AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H
```

## Reference calculator conformance

Repository: https://github.com/kenhuangus/aivss-v1-candidate

The reference calculator (`aivss-calc` 1.0.1) implements AIVSS 1.0 Level 1/2
assessment mechanics:

1. Resolves Exploit Maturity (`E`) from the evidence ladder before severity
2. Requires a complete Agentic AI Profile for every assessment
3. Accepts ASI01–ASI10 and MAESTRO-extended taxonomy metadata
4. Emits SSVC/BOD decision tracks at Level 2

The `legacy` subcommand reproduces withdrawn v0.x uplift scores for migration
comparison only and must not be used for AIVSS 1.0 compliance.

## Install and verify

```bash
pip install -e ".[dev]"
pytest   # full suite
aivss-calc verify
```

The in-browser calculator has its own end-to-end tests. They need Playwright, a
Chromium browser, and network access, so they are skipped unless explicitly
enabled:

```bash
pip install -e ".[dev,browser]"
playwright install chromium
AIVSS_BROWSER_TESTS=1 pytest tests/test_web_calculator_browser.py
```

## CLI

```bash
aivss-calc assess examples/asi06-example.json
aivss-calc profile "CVSS:4.0/..." --aivss-vector "AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H"
aivss-calc rubric
aivss-calc demo
```

## Web calculator

Launch **`aivss-calc demo`** and open http://127.0.0.1:8765/ to score a finding
interactively: pick the CVSS v4.0 and Agentic AI metrics (or paste a vector
pair), and the page shows the CVSS-BTE severity with its qualitative rating, the
Agentic AI Effect Class, the MacroVector, and — when enabled — the SSVC / BOD
26-04 remediation timeline with the A2 overlay. The ten OWASP Agentic Top 10
reference scenarios are available as presets, and every result has a shareable
link that carries the vectors.

The page runs this package itself through
[Pyodide](https://pyodide.org/) (`web/engine.js` loads the bundle served at
`py/aivss_calc.zip`), so browser results come from the same code as the CLI and
cannot drift from it. Loading the runtime takes a few seconds on first visit and
needs network access to the Pyodide CDN; the CLI works offline.

Live demo (GitHub Pages): see **[Try it online](#-try-it-online)** at the top of this README.

Regenerate all OWASP ASI reference inputs and the summary from the single
scenario catalog:

```bash
python examples/generate_asi_examples.py
```

These are synthetic format and calculation fixtures, not incidents, an
empirical validation corpus, or evidence that the candidate model predicts
outcomes. ASI category names come from the
[OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/);
OWASP does not endorse this AIVSS candidate.

## Presentation slides

An interactive 23-slide HTML deck covers the AIVSS 1.0 decoupled architecture,
CVSS v4.0 interpretations, the 8-metric profile, SSVC / CISA BOD 26-04 timelines,
and the EchoLeak (`CVE-2025-32711`) case study — see the
**[Try it online](#-try-it-online)** link at the top for the live deck.

- **Live presentation (GitHub Pages):** https://kenhuangus.github.io/aivss-v1-candidate/slides.html
- **Repository source:** [slides.html](slides.html) (mirrored at [docs/slides.html](docs/slides.html))
- **Navigation controls:** Arrow keys or Space to advance, `F` for fullscreen, `M` to toggle Grid View, and `G` to jump to a specific slide.

## Authoritative documents

- [Masterclass slides](slides.html): interactive 23-slide deck on architecture, scoring, and remediation ([Live](https://kenhuangus.github.io/aivss-v1-candidate/slides.html))
- [SSVC / BOD 26-04 Layer 3](docs/SSVC.md): decision table, namespaces, overlay rules
- [Metric rubric](docs/METRIC-RUBRIC.md): value definitions and decision rules
- [Scoring](docs/SCORING.md): algorithms, invariants, and experimental status
- [CVSS mapping](docs/CVSS-MAPPING.md): overlap and separation rules
- [Validation](docs/VALIDATION.md): supported claims and calibration gates
- [Input schema](schemas/aivss-assessment-input-v1.0.json)
- [Report schema](schemas/aivss-report-v1.0.json)

`aivss_calc/data/cvss_v4_lookup.json` is derived from the FIRST CVSS v4.0
reference implementation under the BSD-2-Clause license; see
[third-party notices](THIRD_PARTY_NOTICES.md). CVSS is owned and managed by
FIRST.Org, Inc. Its use does not imply FIRST endorsement of AIVSS.

## License

AIVSS is an OWASP project. Unless otherwise noted, the contents of this
repository are licensed under the [Apache License, Version 2.0](LICENSE).
Third-party components remain under their own licenses; see
[third-party notices](THIRD_PARTY_NOTICES.md).
