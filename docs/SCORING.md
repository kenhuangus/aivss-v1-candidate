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
Any `X` makes the profile incomplete and produces effect class `AX` when a
classifying metric is unknown.

## Agentic Effect Class

LC, CP, AP, and SR determine an ordinal class:

1. `AX` if any of LC, CP, AP, or SR is `X`.
2. `A2` if `AP:L`, `LC:{D,I} + CP:C`, or `LC:D + SR:R`.
3. `A0` if `LC:N + CP:N + AP:N + SR:U`.
4. `A1` otherwise.

EX, PT, CA, and TD do not affect this class. They are descriptive assurance
metadata on the exploitation path and do not modify the severity number.
`A0` means “no class-based promotion”; it does not mean “no agentic risk.”
Reports label the class `candidate-unvalidated`: its boundaries are explicit
and deterministic, but have not yet passed the gates in
[VALIDATION.md](VALIDATION.md).

## CVSS result

`cvss_bte` is produced from the separate, valid CVSS v4.0 vector. AIVSS does
not modify CVSS metric definitions, constants, ordering, or the official CVSS
score. Consumers must always retain and display `cvss_bte`.

## Normative AIVSS severity

The normative AIVSS severity number equals CVSS-BTE:

```text
aivss = cvss_bte
```

Agentic AI metrics are parallel metadata. EX, PT, CA, and TD record assurance
deficits but do not apply numeric additive uplift to the severity number.

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

Vulnrichment values take precedence. For non-KEV CVEs where both Automatable and
Technical Impact are unavailable, CISA BOD 26-04 implementation guidance directs
a 60-day timeline (not a table lookup using default no/total, which can wrongly
yield 14 days when the asset is publicly exposed). When Publicly Exposed is
unknown, it defaults to Yes. KEV entries must use the metadata CISA publishes
for them; the calculator does not silently default missing KEV data. The result is labelled a compliance
result only when `fceb_bod_2604_scope=true`; otherwise
it is labelled informative CVE guidance because the directive does not apply
to every organization or system.

For a non-CVE finding, Automatable and Technical Impact must be supplied
explicitly. The table result is labelled `informative_bod_26_04_analogy`,
`compliance_applicable=false`, and is not a regulatory deadline. AIVSS never
derives these inputs from SR or CVSS.

The candidate overlay advances at most one timeline tier when the Agentic AI
Effect Class is `A2`. Triggers do not stack. It never creates a forensic-triage
obligation and never removes one: a CISA `3DF` result remains `3DF`.

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
