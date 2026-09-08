# Validation and Defensibility

## Claims supported by this candidate

The repository currently supports these claims:

1. CVSS v4.0 inputs remain separate and independently reproducible.
2. When the Agentic AI Profile is present, every report records all eight
   metrics, one coherent path, and evidence per metric. The profile may be
   omitted; a missing profile is not A0 and does not assert an effect class.
3. Unknown classifying evidence is represented explicitly as effect class `AX`.
4. Effect-class algorithms are deterministic, exact, and exhaustively tested
   over their finite input domains.
5. Normative AIVSS severity equals CVSS-BTE; assurance metrics are
   descriptive metadata only.
6. CISA BOD 26-04 compliance results are separated from non-CVE analogies and
   from the AIVSS overlay.
7. A forensic-triage requirement is never removed by the overlay.

The repository does **not** yet support claims that the candidate
effect-class boundaries, remediation overlay, or priority bands predict loss,
exploitation, or optimal remediation decisions.

## Candidate hypotheses

The following outputs are retained to enable evaluation, not to assert
validity:

| Output | Current status |
|---|---|
| A0/A1/A2 effect-class boundaries | candidate-unvalidated |
| A2 remediation acceleration | experimental-uncalibrated |
| AIVSS-P portfolio order | organization-local-uncalibrated |

Reports expose these statuses in machine-readable fields. Documentation,
examples, and CLI output must use the same labels.

## Synthetic fixtures and AIVSS-P (Phase 6)

Worked examples under `examples/` are **synthetic reference fixtures** generated
from the scenario catalog. They illustrate Mode 1 scoring paths only; they are
not field measurements or loss estimates.

AIVSS-P (Level 3) is an organization-internal priority index. It is **not**
monetary loss. Unknown likelihood, reach, or criticality MUST be recorded as
unknown (`X`) and excluded from the numeric index — unknown is not zero.
Organizations MUST publish their qualitative→numeric mapping internally before
using band cut-points (provisional percentile bands use an artificial uniform
grid and require corpus recalibration).

When AIVSS-P band conflicts with BOD baseline (e.g., Immediate vs 60D), the
`cisa:BOD2604:1.0.0` outcome is the federal compliance obligation. Release
gates evaluate in order; the most-restrictive applicable gate wins. Waivers
document deployment exceptions; they are not product roadmaps. TD — not TA —
is the traceability metric for gate conditions. Mode 2 and candidate_adjusted
triggers are withdrawn.

## Required evidence before a stable scoring claim

A stable release may not label a numeric output normative until all gates pass:

### Content and construct validity

- At least five independent Agentic AI security practitioners review every
  metric definition and boundary with recorded disagreements.
- At least 100 adjudicated findings span all ten ASI categories, every metric
  value, non-agentic controls, and multi-path cases.
- Reviewers confirm that each metric measures its stated construct and does
  not merely restate CVSS impact or another AIVSS metric.

### Inter-rater reliability

- At least three blinded assessors score each validation finding from the same
  evidence packet.
- Weighted kappa or Krippendorff’s alpha is at least 0.70 for every ordinal
  metric and the effect class.
- Disagreement analysis results in rubric changes or documented acceptance;
  aggregate agreement must not hide a failing metric.

### Weight and class calibration

- Use data from at least five organizations and 500 findings, with a held-out
  organization-level test set.
- Pre-register the target outcome. Suitable targets include blinded expert
  pairwise severity ordering, bounded incident loss, or remediation outcome;
  do not train against the proposed AIVSS score itself.
- Fit weights and class rules on the training set. Do not select constants by
  visual preference or by matching examples.
- On holdout data, show improvement over CVSS-BTE alone with confidence
  intervals and report subgroup performance by ASI category and organization.
- Reject a scalar model if direction, ranking, or calibration is unstable
  under bootstrap resampling or plausible missing-data assumptions.

### Saturation and sensitivity

- Fewer than 5% of representative findings may lose ordering solely because of
  the 10.0 cap, or the publication format must retain an uncapped ordering
  field.
- Publish one-at-a-time and global sensitivity analysis for every weight and
  class threshold.
- Demonstrate monotonicity for intended ordinal directions and document every
  intentional interaction.

### Operational validation

- Validate input and report schemas against positive and negative corpora.
- Reproduce all scores with an independent implementation.
- Verify decision-table results against the current official CISA directive.
- Run migration tests across every published vector and report version.

## Versioning policy

- Patch: implementation correction with no output change.
- Minor: backward-compatible fields or clarified evidence guidance.
- Major: metric value set, decision boundary, weight, formula, vector syntax,
  or report semantics change.

The package, report, rubric, and extension-vector versions are separate fields
with one source of truth in `aivss_calc/versions.py`.

## Reproducibility checklist

Each validation publication must include the anonymized evidence packets or a
fully specified synthetic substitute, assessor instructions, adjudication
records, analysis code, random seeds, missing-data policy, train/test split,
all rejected models, and confidence intervals. Without those artifacts,
“validated,” “calibrated,” and “normative” are prohibited release terms.
