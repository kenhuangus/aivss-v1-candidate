# CVSS v4.0 vs Agentic AI Metrics

AIVSS is CVSS-compatible: the CVSS vector is scored first; Agentic AI metrics extend it. This document explains what CVSS already captures, what AIVSS adds, and what remains out of scope for v1.0.

## What CVSS covers (score honestly in CVSS)

| Concern | CVSS home | Notes |
|---------|-----------|-------|
| Downstream system impact from tool reach | **SC / SI / SA** | Subsequent-system confidentiality, integrity, availability |
| Vulnerable-system impact | **VC / VI / VA** | Direct harm to the agent host or primary asset |
| Attack vector and prerequisites | **AV / AC / AT / PR / UI** | Network path, complexity, auth, user interaction |
| Agent credential scope | **PR** (Privileges Required) | Service account vs user vs none |
| Human-in-the-loop vs autonomous action | **UI** (User Interaction) | Whether a human must approve or trigger |
| Exploit maturity | **E** (Threat metric) | PoC, active, etc. |

Assessors must not double-count downstream impact: if a tool can exfiltrate customer data, that belongs in **SC/SI**, not as a separate AIVSS uplift on top of an already-high SC.

## What CVSS does not name (AIVSS adds)

| Concern | Partially in CVSS? | AIVSS home | Why separate |
|---------|-------------------|------------|--------------|
| Extension type and surface (tools, MCP, plugins, skills, workflows) | **No** | **EX** | CVSS has no metric for *which extension mechanisms* exist on the path; SC/SI/SA only describe impact if invoked |
| Post-incident traceability of agent reasoning and tool calls | **No** | **TD** | Operational risk when scope cannot be bounded |
| Language-mediated control path | **No** | **LC** | Prompt/injection reach to privileged behaviour |
| Cross-session context persistence | **No** | **CP** | Memory, RAG, training-data carryover |
| Cross-boundary agent propagation | Partially **AP** via SC scope | **AP** | Trust-boundary crossing between agents/tenants |
| Stochastic exploit reliability under retry | Partially **AC** | **SR** | Agent non-determinism and retry economics |

ASI02 (tool misuse) and ASI04 (supply chain / untrusted extensions) are **taxonomy categories** for reporting, not numeric metrics. **EX** is the scored factor for extension surface on the attack path.

## Agentic Effect Class vs numeric factors

| Mechanism | Affects Agentic Effect Class | Affects numeric AIVSS |
|-----------|------------------------------|------------------------|
| LC, CP, AP, SR | Yes (boolean ladder) | No (Mode 1); yes via Mode 2 promotion |
| EX:W with LC∈{D,I} | Yes (A2 rule) | Yes (EX_delta) |
| EX (all values) | Only EX:W + LC rule | Yes (EX_delta) |
| TD (all values) | No | Yes (TD_delta); TD:H also advances overlay |

## Known gaps (not in CVSS or AIVSS v1.0 numeric model)

| Concern | Status in v1.0 |
|---------|----------------|
| Model/provider trust and provenance | ASI04 classification only; no numeric factor |
| Multi-agent orchestration depth | Partially **AP** + **EX:W** when workflows span agents |
| Cost / rate-limit / token abuse | Out of scope for v1.0 severity |
| Self-modification and training-time attacks | ASI categories; no dedicated metric |
| Regulatory / privacy jurisdiction | Organizational context (AIVSS-P), not base score |

These may be addressed in future rubric versions after calibration.

## Worked separation example

An agent with an MCP server that can call `delete_user` on a production API:

1. Set **SC/SI/SA** to reflect harm if the tool succeeds.
2. Set **EX:M** or **EX:W** depending on whether only that MCP bundle exists or many dynamic extensions are loadable.
3. Set **LC** for how attacker language reaches the tool-invocation path.
4. Set **TD** for whether tool calls and reasoning traces are auditable after an incident.

Do not inflate CVSS-BTE for “has tools” and also set **EX:W** without justification — EX measures the *exploitation-path* extension surface, not generic product marketing feature lists.
