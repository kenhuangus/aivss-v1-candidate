# AIVSS 2.0 Candidate

AIVSS is a candidate extension profile for describing vulnerabilities in
Agentic AI systems. It keeps the official CVSS v4.0 vector and score intact and
records eight Agentic AI metrics in a separate extension vector.

Status: **candidate**. The metric rubric and conformance rules are testable.
The numeric adjustment, MacroVector experiment, remediation overlay, and
organization-local priority index are **not empirically calibrated** and must
not be presented as standards, probabilities, or regulatory requirements.
The [extension manifest](aivss-extension.json) records
`first_validation_status: not-submitted`; FIRST has not validated or endorsed
this candidate.

## Model

- **Mode 1 (normative):** `AIVSS = CVSS-BTE` — agentic metrics are parallel metadata
- **Candidate adjusted (experimental):** `min(10, CVSS-BTE + EX + PT + CA + TD)`
- Classifying metrics: **LC, CP, AP, SR**
- Adjustment metrics: **EX, PT, CA, TD** (v1.0 alias: **TA** Traceability Avoidance)
- Unknown evidence value: **X**
- Effect classes: **A0, A1, A2, AX**

Layer 3 remediation uses CERT/CC SSVC decision table **`cisa:DT_BOD2604:1.0.0`**
(BOD 26-04), with Agentic AI Effect Class **A2** as a fifth transparent extension
input. See [docs/SSVC.md](docs/SSVC.md).

Every assessment covers one coherent exploit path and supplies all eight
metrics plus a rationale for each. `AX` and a withheld candidate score are
used when evidence is insufficient.

CVSS and AIVSS vectors are separate, following the
[CVSS v4.0 Extensions Framework](https://www.first.org/cvss/v4.0/user-guide):

```text
CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P
AIVSS:2.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H
```

## Install and verify

```bash
pip install -e ".[dev]"
pytest
aivss-calc verify
```

## CLI

```bash
aivss-calc assess examples/asi06-example.json
aivss-calc profile "CVSS:4.0/..." --aivss-vector "AIVSS:2.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H"
aivss-calc rubric
aivss-calc demo
```

Launch **`aivss-calc demo`** to open the OWASP Agentic Top 10 dashboard at
http://127.0.0.1:8765/ — Mode 1 scores, candidate scores, effect classes, and
SSVC/BOD remediation timelines for all ten ASI reference scenarios.

Live demo (GitHub Pages): https://kenhuangus.github.io/aivss-v1-candidate/

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

## Authoritative documents

- [SSVC / BOD 26-04 Layer 3](docs/SSVC.md): decision table, namespaces, overlay rules
- [Metric rubric](docs/METRIC-RUBRIC.md): value definitions and decision rules
- [Scoring](docs/SCORING.md): algorithms, invariants, and experimental status
- [CVSS mapping](docs/CVSS-MAPPING.md): overlap and separation rules
- [Validation](docs/VALIDATION.md): supported claims and calibration gates
- [2.0 migration](docs/MIGRATION-2.0.md): breaking changes from draft 1.x
- [Input schema](schemas/aivss-assessment-input-v2.0.json)
- [Report schema](schemas/aivss-report-v2.0.json)

`aivss_calc/data/cvss_v4_lookup.json` is derived from the FIRST CVSS v4.0
reference implementation under the BSD-2-Clause license; see
[third-party notices](THIRD_PARTY_NOTICES.md). CVSS is owned and managed by
FIRST.Org, Inc. Its use does not imply FIRST endorsement of AIVSS.
