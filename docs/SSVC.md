# SSVC integration in AIVSS Layer 3

AIVSS remediation timelines are grounded in [Stakeholder-Specific Vulnerability
Categorization (SSVC)](https://certcc.github.io/SSVC/) (Householder et al., 2019).
CISA operationalized SSVC for federal agencies through [Binding Operational
Directive 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk)
(CISA, 2026).

## Decision table

The calculator transcribes CERT/CC **Table 1** (16 rows) from the published
deployer decision table:

| Artifact | Namespace |
|----------|-----------|
| Decision table | `cisa:DT_BOD2604:1.0.0` |
| Outcomes | `cisa:BOD2604:1.0.0` |
| Source | [CERT/CC CISA BOD 26-04 Response Model](https://certcc.github.io/SSVC/howto/cisa_response/) |

## Decision points

| Input | SSVC namespace | Source in AIVSS |
|-------|----------------|-----------------|
| In KEV | `cisa:KEV:1.0.0` | Exploitation evidence ladder |
| Publicly exposed | `cisa:PE:1.0.0` | `publicly_exposed` (asset owner) |
| Automatable | `ssvc:A:2.0.0` | Vulnrichment or explicit input |
| Technical impact | `ssvc:TI:1.0.0` | Vulnrichment or explicit input |
| Agentic AI Effect Class | `aivss:effect_class:1.0.0` | AIVSS fifth-input extension |

## Overlay rules

1. The unmodified BOD/SSVC outcome is always reported separately from any AIVSS
   recommendation.
2. When the Agentic AI Effect Class is **A2**, the recommended timeline advances
   **one SSVC outcome tier** (stopping at 3D; never into 3DF).
3. **TA** (Traceability Avoidance), aliased as **TD** in v2.0 candidate vectors,
   is mandatory metadata — it does **not** modify severity (Mode 1) or the BOD
   outcome.
4. **EPSS** is recorded with a mandatory observation date but does not select the
   exploitation ladder rung or change the decision table lookup.

## API surface

Every `decision` block in an assessment report includes an `ssvc` object:

```json
{
  "ssvc": {
    "methodology": "Stakeholder-Specific Vulnerability Categorization (SSVC)",
    "decision_table": "cisa:DT_BOD2604:1.0.0",
    "outcome_namespace": "cisa:BOD2604:1.0.0",
    "decision_point_namespaces": {
      "in_kev": "cisa:KEV:1.0.0",
      "publicly_exposed": "cisa:PE:1.0.0",
      "automatable": "ssvc:A:2.0.0",
      "technical_impact": "ssvc:TI:1.0.0",
      "agentic_ai_effect_class": "aivss:effect_class:1.0.0"
    }
  }
}
```

## References

- Householder, A., et al. (2019). SSVC: Stakeholder-Specific Vulnerability Categorization. https://certcc.github.io/SSVC/
- Koo, H., et al. (2025). What's New in SSVC. https://www.sei.cmu.edu/blog/whats-new-in-ssvc-build-explore-and-evolve-your-decision-models/
- CISA (2026). BOD 26-04. https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
- CERT/CC (2026). CISA BOD 26-04 Response Model. https://certcc.github.io/SSVC/howto/cisa_response/
