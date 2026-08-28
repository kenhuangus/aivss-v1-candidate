# AIVSS Candidate Algorithms

This document defines calculator behavior for AIVSS 1.0, rubric
1.0.0. Normative metric meanings live only in
[METRIC-RUBRIC.md](METRIC-RUBRIC.md).

## Assessment unit

An assessment represents one finding on one coherent exploit path. Do not take
the worst value of each metric from different paths and combine them into a
synthetic profile. Score materially different paths separately and retain a
stable `path_id`.

All eight metrics are required. Use `X` when evidence cannot resolve a metric.
Any `X` makes the profile incomplete, produces effect class `AX` when a
classifying metric is unknown, and withholds numeric candidate outputs.

## Agentic Effect Class

LC, CP, AP, and SR determine an ordinal class:

1. `AX` if any of LC, CP, AP, or SR is `X`.
2. `A2` if `AP:L`, `LC:{D,I} + CP:C`, or `LC:D + SR:R`.
3. `A0` if `LC:N + CP:N + AP:N + SR:U`.
4. `A1` otherwise.

EX, PT, CA, and TD do not affect this class. This prevents one factor from
being counted once in class promotion and again as an additive adjustment.
`A0` means “no class-based promotion”; it does not mean “no agentic risk.”
Reports label the class `candidate-unvalidated`: its boundaries are explicit
and deterministic, but have not yet passed the gates in
[VALIDATION.md](VALIDATION.md).

## CVSS result

`cvss_bte` is produced from the separate, valid CVSS v4.0 vector. AIVSS does
not modify CVSS metric definitions, constants, ordering, or the official CVSS
score. Consumers must always retain and display `cvss_bte`.

## Experimental candidate adjustment

The calculator exposes this hypothesis for research and sensitivity testing:

```text
EX = W:0.40, M:0.15, N:0.00
PT = H:0.30, M:0.10, L:0.00
CA = W:0.30, M:0.10, N:0.00
TD = H:0.50, M:0.20, L:0.00

delta = EX + PT + CA + TD
raw_aivss = CVSS-BTE + delta
aivss = round_half_up(min(10.0, raw_aivss), 1)
```

Zero-impact invariant: if CVSS-BTE is `0.0`, `raw_aivss` and `aivss` remain
`0.0`. Assurance deficits do not create vulnerability impact by themselves.

All arithmetic uses decimal values and final half-up rounding. Reports include
the raw value, each component, the total delta, and whether the 10.0 cap was
reached.

These weights are ordinal judgments expressed as cardinal increments. They
have not been fitted to incident loss, expert rankings, exploit prevalence, or
inter-rater data. Therefore the output status is always
`experimental-uncalibrated`; it is not a normative AIVSS score. The release
gates for changing that status are in [VALIDATION.md](VALIDATION.md).

## Experimental MacroVector mapping

The optional MacroVector experiment maps A1 and A2 to adjacent CVSS
equivalence classes before applying the candidate adjustment. It is disabled
in reports unless `include_experimental_mode2` is true.

This mapping was not produced by FIRST’s CVSS expert-ranking process. It must
not be described as a CVSS score or FIRST-endorsed result. Saturation and the
pre-adjustment MacroVector value are reported explicitly.

## Decision support

For a CVE, the calculator can apply the published CISA BOD 26-04 table using:

- KEV status
- asset exposure
- Automatable
- Technical Impact

Reports identify the transcribed decision model as `cisa:BOD2604:1.0.0` and
retain links to both the machine-readable
[CERT/CC response model](https://certcc.github.io/SSVC/howto/cisa_response/)
and the CISA directive.

Vulnrichment values take precedence. For non-KEV CVEs with missing metadata,
the published BOD defaults are `Automatable=no` and `Technical Impact=total`.
KEV entries must use the metadata CISA publishes for them; the calculator does
not silently default missing KEV data. The result is labelled a compliance
result only when `fceb_bod_2604_scope=true`; otherwise
it is labelled informative CVE guidance because the directive does not apply
to every organization or system.

For a non-CVE finding, Automatable and Technical Impact must be supplied
explicitly. The table result is labelled `informative_bod_26_04_analogy`,
`compliance_applicable=false`, and is not a regulatory deadline. AIVSS never
derives these inputs from SR or CVSS.

The candidate overlay advances at most one timeline tier if `A2` or `TD:H`.
Triggers do not stack. It never creates a forensic-triage obligation and never
removes one: a CISA `3DF` result remains `3DF`.

See the official
[BOD 26-04 directive](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk)
and
[implementation guidance](https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk).

## Organization-local priority

AIVSS-P is retained only as an optional, organization-local, uncalibrated
ordering aid. Its output is not comparable across organizations and is omitted
from public reference examples. Organizations must calibrate its inputs and
bands against their own outcome data before operational use. They must also
define residual likelihood so it does not re-count CVSS Threat, SR, exposure,
or other evidence already present in the assessment.
