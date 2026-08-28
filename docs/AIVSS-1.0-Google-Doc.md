# AIVSS 1.0 — Agentic AI Vulnerability Scoring System

**Version:** 1.0
**Status:** Reference specification
**Reference calculator:** `tools/aivss-calc` (95 tests, exact assertions)
**Canonical risk taxonomy:** OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)

This document is a standalone specification. It assumes no prior reading of earlier AIVSS drafts, review memos, or Appendix E. Every normative term is defined here or cited to an external authority.

---

## 1 Executive Summary

The **Agentic AI Vulnerability Scoring System (AIVSS)** is a reference framework and open-source calculator for rating the **cybersecurity severity** of vulnerabilities in **agentic AI systems** — deployed software that can plan, use tools, retain context, and act with some autonomy.

AIVSS extends CVSS v4.0 with agent-specific interpretation rules and a parallel Agentic AI Profile, then maps findings to federal remediation timelines. The specification scores all ten OWASP Agentic AI risk categories (ASI01–ASI10); representative findings range from **ASI01 Agent Goal Hijack** (AIVSS 9.2) to **ASI07 Insecure Inter-Agent Communication** (7.1) — see Section 2.1 and Section 14.

Version 1.0 adopts the **OWASP Top 10 for Agentic Applications 2026** as its risk classification taxonomy. **Eight of ten** ASI categories trace their research lineage to the original **Agentic AI Core Risks** taxonomy developed by the **OWASP AIVSS project team** [5] as community-driven, open-source security research; OWASP extended coverage with **ASI09 Human–Agent Trust Exploitation** and **ASI10 Rogue Agents**. AIVSS is a **scoring tool, not a taxonomy authority** — it retires its parallel category list for v1.0 and credits the project team's contribution in Section 5. **EPSS** is recorded in every assessment where available but does not modify scores or remediation timelines — rationale in Section 12.3.1. The specification is self-contained: every normative term is defined in the Introduction (Section 2) and Definitions (Section 3), or cited to an external authority.

---

## 2 Introduction

This section introduces the concepts a reader needs before the normative parts of the specification. Each term is **defined first**, then **elaborated** with its role in an AIVSS assessment.

### 2.1 What AIVSS assesses

**Definition — Agentic AI system.** A deployed software system that combines a language or reasoning model with tool access, execution autonomy, persistent state, and network reach. (Full definition: Section 3.1.)

**Elaboration.** AIVSS scores the **security consequences of vulnerabilities** in such systems, classified under the **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10) [4]. That Top 10 synthesizes cross-industry open-source security guidance — prominently including the **OWASP AIVSS project team's** original **Agentic AI Core Risks** taxonomy [5]. **Eight of ten** OWASP ASI categories trace their research lineage directly to that AIVSS work (ASI01–ASI08); **ASI09** and **ASI10** are OWASP additions with no AIVSS predecessor. Full credit, research lineage, and the complete category list are in Section 5.

Representative findings — one per OWASP category, each scored in Section 14:

- **ASI01 Agent Goal Hijack** — attacker redirects a planning agent's objectives through injected instructions (AIVSS 9.2).
- **ASI02 Tool Misuse & Exploitation** — agent applies a legitimate tool in an unsafe way, enabling data exfiltration (AIVSS 8.3).
- **ASI03 Identity & Privilege Abuse** — stolen service credential drives lateral actions across agent workflows (AIVSS 8.5).
- **ASI04 Agentic Supply Chain Vulnerabilities** — compromised MCP plugin supplies malicious tool definitions at runtime (AIVSS 8.8).
- **ASI05 Unexpected Code Execution** — code interpreter executes attacker-supplied shell commands (AIVSS 8.9).
- **ASI06 Memory & Context Poisoning** — adversarial data planted in the agent's context store biases later sessions (AIVSS 7.8; worked example Section 15).
- **ASI07 Insecure Inter-Agent Communication** — unsigned agent-to-agent messages allow instruction relay (AIVSS 7.1).
- **ASI08 Cascading Failures** — faulty planner triggers downstream orchestration failures (AIVSS 7.9).
- **ASI09 Human–Agent Trust Exploitation** — forged agent summaries social-engineer a human approver (AIVSS 7.0).
- **ASI10 Rogue Agents** — compromised worker agent operates outside policy with legitimate credentials (AIVSS 8.6).

AIVSS does not assess whether a model is "safe" or "aligned" in the broader AI-safety sense; it measures cybersecurity impact using the same 0–10 severity scale as CVSS v4.0 [1].

### 2.2 Assessment outputs

Every conformant AIVSS assessment produces four outputs. Each is defined below, then explained in context.

**2.2.1 Severity score**

**Definition — Severity score.** A numeric rating from 0.0 to 10.0 on the scale defined by the Common Vulnerability Scoring System (CVSS) version 4.0 [1], representing the technical severity of a vulnerability finding. In AIVSS output it is always prefixed `AIVSS:` (for example, `AIVSS:7.8`) to distinguish it from a vendor-supplied or NVD-published CVSS score for the same underlying flaw.

**Elaboration.** The severity score is the primary output of Mode 1 (normative) scoring. It equals **CVSS-BTE** — the CVSS score computed from Base, Threat, and Environmental metric groups without organizational modifiers (Section 3.2). AIVSS applies agent-specific **interpretation rules** when building the CVSS vector (Section 9) but does not arithmetically add agentic factors on top of the finished number. An **ASI06** memory-poisoning finding assessed at CVSS-BTE 7.8 remains `AIVSS:7.8`; agentic context is recorded separately in the Agentic AI Profile.

**2.2.2 Agentic AI Profile**

**Definition — Agentic AI Profile.** A structured extension to the CVSS vector string consisting of five named dimensions — **LC** (Language-Mediated Control), **CP** (Context Persistence), **AP** (Agentic Propagation), **SR** (Stochastic Exploit Reliability), and **TD** (Traceability Deficit / **Agent Untraceability**) — that describe agent-specific properties not already captured by CVSS Base metrics. The first four drive AI Effect Class; **TD is a mandatory risk factor** from the original OWASP AIVSS taxonomy [5] and does not affect the Mode 1 severity number (Section 5.6, Section 10.5).

**Elaboration.** CVSS v4.0 was designed for traditional software vulnerabilities. Agentic systems introduce properties that CVSS can partially represent but does not name explicitly — illustrated by ASI categories such as **ASI01** (language-mediated goal hijack → LC), **ASI06** (persistent poisoned context → CP), **ASI07** (cross-agent instruction relay → AP), and **Agent Untraceability** (no OWASP ASI equivalent → TD). The Agentic AI Profile records residual agentic properties after everything mappable into CVSS has been scored there (Section 2.3, Section 9). **TD** is always assessed because OWASP Top 10 has no ASI category for Agent Untraceability (Section 5.6). The Agentic AI Profile does not modify the Mode 1 severity number; it provides parallel metadata for prioritization, forensic response, remediation escalation, and optional extended scoring.

**2.2.3 AI Effect Class**

**Definition — AI Effect Class.** A three-level boolean classification — **A0** (none), **A1** (present), or **A2** (substantial) — derived from the values of LC, CP, AP, and SR. It summarizes whether the Agentic AI Profile indicates agentic amplification beyond a baseline software vulnerability, without performing arithmetic on the ordinal metric levels (Section 11).

**Elaboration.** The AI Effect Class condenses four ordinal dimensions into a single decision-relevant label. **A2** is assigned in calculator examples such as **ASI01** (goal hijack with LC:D and SR:R), **ASI06** (memory poisoning with LC:D, CP:C, and AP:L), and **ASI07** (unsigned inter-agent messages with AP:L). **A1** appears in **ASI02** (tool misuse contained within the agent's scope) and **ASI09** (human–agent trust exploitation). **A0** means all metrics are at their benign values, or no Agentic AI Profile was supplied — in which case AIVSS equals CVSS-BTE exactly. The class affects remediation timeline escalation (Section 12.4) and optional Mode 2 scoring (Section 13.2); it does not change the Mode 1 severity number.

**2.2.4 Remediation timeline recommendation**

**Definition — Remediation timeline recommendation.** A categorical urgency label — Fix on System Upgrade, 60 days, 14 days, 3 days, or 3 days with forensic triage (3DF) — derived from CISA Binding Operational Directive 26-04 (BOD 26-04) [3], optionally advanced by one tier when the AI Effect Class is A2. AIVSS escalation never produces 3DF (Section 12.4).

**Elaboration.** Severity alone does not determine how quickly a vulnerability must be remediated. Since June 10, 2026, BOD 26-04 [3] has been the federal remediation standard for Federal Civilian Executive Branch agencies, replacing CVSS-severity-driven timelines with a four-variable decision model (KEV status, public exposure, automatable, technical impact). AIVSS consumes BOD 26-04 verbatim as a 16-row lookup table (Section 12.2) and adds the AI Effect Class as a fifth decision input. When the class is A2, the recommended timeline advances one tier (for example, 60 days → 14 days), stopping at the 3-day ceiling. The unmodified BOD result is always reported alongside the AIVSS recommendation; for FCEB agencies, BOD 26-04 is the compliance obligation.

### 2.3 Core architectural rule — Mode 1

**Definition — CVSS-BTE.** The CVSS v4.0 score computed from the Base, Threat, and Environmental metric groups, excluding organizational (Modified Base / Modified Threat / Security Requirements) overlays. Computed using proper CVSS v4.0 interpolation per FIRST `cvss_lookup.js` [1, 7].

**Definition — Mode 1 (normative scoring).** The default AIVSS scoring mode in which `AIVSS = CVSS-BTE`. AI metrics are recorded in the Agentic AI Profile as parallel metadata and do not arithmetically modify the severity number.

**Elaboration.** AIVSS 1.0 adopts Jeff Williams' Appendix E Option 3 [8] as its governing architecture: **map everything possible into CVSS**; **score only the AI-specific residual** as named metrics (LC, CP, AP, SR, TD); **integrate any extension through a lookup table**, not arithmetic uplift. This means the primary severity number is always a score that exists within the CVSS measurement model — AIVSS never invents a number the CVSS SIG's process did not produce. Agentic properties already representable in CVSS (tool reach → SC/SI/SA; agent credential → PR; autonomous execution → UI:N) must be scored in CVSS, not duplicated in the Agentic AI Profile (Section 9.3). A separate provisional Mode 2 uses MacroVector promotion from FIRST's lookup table (Section 13.2); it is not suitable for compliance gates.

### 2.4 Taxonomy rule

**Definition — Risk taxonomy.** A canonical list of named risk categories used to classify security findings for traceability, reporting, and worked examples. In AIVSS 1.0, the taxonomy is the OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10) [4].

**Definition — Taxonomy authority.** The organization responsible for maintaining, peer-reviewing, and updating a risk taxonomy over time.

**Elaboration.** AIVSS is a **scoring tool**, not a taxonomy authority. Version 1.0 **adopts OWASP ASI01–ASI10** [4] for primary risk classification and **retires** the parallel ten-category list — except **Agent Untraceability**, which OWASP did not adopt and which AIVSS **retains as the mandatory TD risk factor** (Section 5.6). The earlier taxonomy was developed by the **OWASP AIVSS project team** [5] as community-driven, open-source research; that work established the foundational risk themes that informed the OWASP Top 10. **Eight categories became ASI01–ASI08**; **ASI09** and **ASI10** are OWASP additions; **Agent Untraceability** lives on as TD. See Sections 5.1–5.5 for full credit and crosswalk.

### 2.5 What AIVSS does not score

**Definition — Out-of-scope measurement domains.** The following are explicitly excluded from AIVSS scoring:

<!--table:Out-of-scope measurement domains-->
| Domain | What it measures |
|---|---|
| Model alignment | Whether a model adheres to intended values and instructions under adversarial pressure |
| Jailbreak resistance | Robustness against deliberate prompt manipulation designed to bypass safety guardrails |
| Content safety | Whether outputs are toxic, harmful, or policy-violating |
| Bias | Systematic unfair treatment across demographic or other groups |
| Fairness | Equitable outcomes across user populations |

**Elaboration.** These are distinct measurement problems with distinct methodologies and evidence bases. The CVSS Special Interest Group has cautioned that merging software quality, ethics, privacy, and cybersecurity into a single severity number "creates dangerously misleading perceptions" [2]. AIVSS follows that guidance: it scores **cybersecurity severity** only. Where a model-behaviour assessment is in use elsewhere in an organization, its output may inform the exploitation evidence ladder (Section 12.3) but does not enter any AIVSS score. Full scope and non-goals are in Section 4.

---

## 3 Definitions and Terminology

This section defines every acronym and concept used normatively in later sections.

### 3.1 Systems and findings

**Agentic AI system.** A deployed software system that combines a language or reasoning model with **tool access** (APIs, databases, code execution, messaging), **execution autonomy** (can invoke tools without per-action human approval), **persistent state** (memory, vector stores, conversation history), and **network reach** (can interact with external services or other agents). Examples mapped to OWASP ASI risk surfaces: a sales agent with CRM write access (**ASI02** tool misuse, **ASI03** identity abuse); a coding assistant with repository and shell access (**ASI05** unexpected code execution); a multi-agent orchestration platform (**ASI07** insecure inter-agent communication, **ASI08** cascading failures).

**Vulnerability.** A weakness in a system's design, implementation, or configuration that can be exploited to cause a security-relevant impact, as defined by CVSS v4.0 [1].

**Finding.** A specific instance of a vulnerability assessed in a particular deployment context (a named agent, tenant, and tool configuration).

**Risk category (ASI).** One of the ten categories in the OWASP Top 10 for Agentic Applications 2026 [4], identified ASI01 through ASI10. Classification is for traceability and worked examples only; the category label does not enter any score formula.

### 3.2 CVSS v4.0 concepts

**CVSS (Common Vulnerability Scoring System).** An open framework maintained by FIRST [1] for describing the severity of software vulnerabilities on a 0–10 scale. CVSS v4.0 uses a vector string of metric abbreviations and values.

**CVSS vector string.** A machine-readable representation such as `CVSS:4.0/AV:N/AC:L/...`. Each slash-separated pair is one metric.

**Base metrics** measure intrinsic properties of the vulnerability independent of environment or threat:

<!--table:CVSS v4.0 Base metrics-->
| Metric | Name | What it measures |
|---|---|---|
| AV | Attack Vector | How the attacker reaches the vulnerable component (Network, Adjacent, Local, Physical) |
| AC | Attack Complexity | Conditions beyond attacker control that must exist (Low, High) |
| AT | Attack Requirements | Deployment or execution conditions required (None, Present) |
| PR | Privileges Required | Privilege level needed before exploitation (None, Low, High) |
| UI | User Interaction | Whether a human must participate beyond the attacker (None, Passive, Active) |
| VC | Vulnerable System Confidentiality impact | Confidentiality loss on the component containing the flaw |
| VI | Vulnerable System Integrity impact | Integrity loss on the component containing the flaw |
| VA | Vulnerable System Availability impact | Availability loss on the component containing the flaw |
| SC | Subsequent System Confidentiality impact | Confidentiality loss on systems reachable through the vulnerable component |
| SI | Subsequent System Integrity impact | Integrity loss on systems reachable through the vulnerable component |
| SA | Subsequent System Availability impact | Availability loss on systems reachable through the vulnerable component |

Impact values are None, Low, or High. FIRST defines precise scoring rules in the CVSS v4.0 specification [1].

**Threat metrics** describe observed exploitation:

<!--table:CVSS v4.0 Threat metrics-->
| Metric | Name | Values |
|---|---|---|
| E | Exploit Maturity | Not Defined, Attacked, POC, Unreported |

**Environmental metrics** adjust severity for a specific deployment. AIVSS uses environmental metrics when computing CVSS-BTE but does not require organizational modifiers for conformance Level 1.

**CVSS-BTE.** The CVSS score computed from Base + Threat + Environmental metric groups, **without** organizational (Modified Base / Modified Threat / Modified Environmental / Security Requirements) overlays. This is the standard "full" CVSS score before per-organization tailoring. AIVSS uses proper CVSS v4.0 interpolation per FIRST `cvss_lookup.js` [1], not merely the MacroVector ceiling.

**MacroVector.** CVSS v4.0 collapses the 2,048 possible Base metric combinations into **270 equivalence classes** (MacroVectors), each assigned an expert-ranked severity score [1, Section 8.2]. A MacroVector is identified by six equivalence-group indices EQ1–EQ6.

**Equivalence groups (EQ1–EQ6).** CVSS v4.0 groups Base metrics that have similar severity effect:

<!--table:MacroVector equivalence groups (EQ1–EQ6)-->
| Group | Metrics grouped |
|---|---|
| EQ1 | AV, PR, UI |
| EQ2 | AC, AT |
| EQ3 | VC (with EQ6 constraint) |
| EQ4 | SC, SI, SA |
| EQ5 | VI |
| EQ6 | VA (with EQ3 constraint) |

### 3.3 AIVSS-specific concepts

**Agentic AI Profile.** The structured extension to a CVSS assessment comprising the AI metric group (LC, CP, AP, SR, TD), its vector fragment, and the derived AI Effect Class. In JSON report output, serialized as the `ai_profile` object (Appendix A).

**AI metric group.** The five-metric vector extension (LC / CP / AP / SR / TD) that forms the core of the Agentic AI Profile (Section 10).

**AI Effect Class (A).** A boolean classification A0, A1, or A2 derived from the AI metric group (Section 11). It affects remediation escalation and optional Mode 2 scoring; it does not change the Mode 1 severity number.

**Mode 1 (normative).** `AIVSS = CVSS-BTE`. The default and only mode suitable for compliance gates, contracts, and SLAs.

**Mode 2 (provisional).** `AIVSS-BTEA = Lookup_AIVSS(EQ1..EQ6, A)` — a MacroVector promotion lookup (Section 13.2). Provisional pending expert calibration; not for compliance gates.

**AIVSS-P.** An optional organization-internal priority index (Level 3 only) combining technical severity with business context (Section 16). Not portable across organizations.

### 3.4 Federal and industry inputs

**CISA.** Cybersecurity and Infrastructure Security Agency (United States).

**BOD 26-04.** CISA Binding Operational Directive 26-04, *Prioritizing Security Updates Based on Risk*, effective June 10, 2026 [3]. It replaces CVSS-severity-driven federal remediation timelines with a four-variable decision model for Federal Civilian Executive Branch (FCEB) agencies.

**KEV (Known Exploited Vulnerabilities catalog).** CISA's authoritative list of CVEs with confirmed active exploitation in the wild [3].

**Vulnrichment.** CISA's program that enriches CVE records with structured fields including Automatable and Technical Impact, used by BOD 26-04 [3].

**EPSS (Exploit Prediction Scoring System).** A FIRST-maintained probability estimate that a CVE will be exploited in the wild within 30 days [11]. In AIVSS, EPSS is **recorded in every report where available** (`epss` + mandatory `epss_date`) but is **metadata only**: it does **not** select an exploitation-ladder rung, set CVSS `E` (Exploit Maturity), modify the Mode 1 severity score, or change the BOD 26-04 timeline lookup. **Why:** see Section 12.3.1 — this is a deliberate architectural choice, not an omission.

**FCEB.** Federal Civilian Executive Branch agencies subject to BOD 26-04.

---

## 4 Scope and Non-Goals

### 4.1 In scope

AIVSS scores the **security consequences of vulnerabilities in deployed agentic systems** — systems with tool access, execution autonomy, persistent state, and network reach, as defined in Section 3.1.

### 4.2 Out of scope

AIVSS does **not** score:

- Model alignment or value adherence
- Jailbreak resistance or prompt-injection robustness as a standalone safety metric
- Content safety, toxicity, bias, or fairness
- Privacy impact beyond what CVSS confidentiality metrics already capture
- Expected financial loss or business risk quantification (that is AIVSS-P's separate, optional domain)

These are distinct measurement problems. Combining them with cybersecurity severity produces misleading single numbers, as noted in the CVSS FAQ [2].

### 4.3 What AIVSS does not claim

1. Endorsement by, compatibility with, or authority from CVSS, FIRST, CISA, or CERT/CC.
2. Probability semantics — no AIVSS output is a calibrated exploitation probability.
3. Empirical validation — **no claim is made that any AIVSS output predicts exploitation.**
4. Standalone federal remediation authority — for FCEB agencies, BOD 26-04 [3] is the compliance obligation; AIVSS recommendations are a non-binding overlay.
5. Cross-organization comparability of AIVSS-P scores.
6. Endorsement of the OWASP Risk Rating Methodology or CWSS as current practice (see Section 16.1 lineage note).

### 4.4 Parameter provenance

Each parameter is **derived** (from an external calibrated source), **asserted** (chosen by the working group), or **calibrated** (fitted to data). Nothing in AIVSS 1.0 is calibrated.

<!--table:Parameter Provenance-->
| Parameter | Value(s) | Status |
|---|---|---|
| CVSS-BTE scores | 270 MacroVector entries | Derived — FIRST `cvss_lookup.js` [1] |
| MacroVector EQ1–EQ6 boundaries | per CVSS v4.0 Section 8.2 | Derived — verbatim from FIRST [1] |
| AI metric value levels (LC/CP/AP/SR/TD) | Section 10 | Asserted — ordinal rubric, never used in arithmetic |
| AI Effect Class ladder | Section 11 | Asserted — boolean rule |
| S2 promotion axes (EQ1, EQ4) | Section 13.2 | Asserted — provisional |
| BOD 26-04 Table 1 timelines | 16 rows | Derived — CISA / CERT-CC `cisa:BOD2604:1.0.0` [3] |
| A2 escalation of one tier | Section 12.4 | Asserted — non-binding overlay |
| AIVSS-P band cut-points | Section 16 | Asserted from output distribution |

### 4.5 Statistical caveat

AI metric levels are **ordinal rubric categories**, not measured quantities. The letter codes carry no claim that "Indirect" sits exactly halfway between "None" and "Direct." AIVSS performs no arithmetic on ordinal AI values. The AI Effect Class is a boolean ladder; Mode 2 is a table lookup. Ordinal factors must not be averaged or multiplied into a severity formula [8].

---

## 5 Risk Taxonomy — OWASP Agentic AI Top 10

### 5.1 Credit — OWASP AIVSS project team

The **Agentic AI Core Risks** taxonomy — the original ten-category classification of security risks in autonomous and agentic AI systems — was developed by the **OWASP AIVSS project team** [5] as community-driven, open-source security research. That work established the foundational risk themes that shaped subsequent industry understanding of agentic threat models and informed the broader OWASP GenAI Security ecosystem.

**Eight of ten** OWASP ASI categories trace their research lineage directly to the original AIVSS core risk taxonomy (see crosswalk in Section 5.5). OWASP extended coverage with two categories that had no AIVSS predecessor: **ASI09 Human–Agent Trust Exploitation** and **ASI10 Rogue Agents**. A ninth original category — **Agent Untraceability** — has no OWASP ASI equivalent; AIVSS **retains it as a mandatory risk factor** carried forward as the **TD (Traceability Deficit)** metric (Section 5.6, Section 10.5).

### 5.2 Cross-industry research leveraged by the OWASP Top 10

The **OWASP Top 10 for Agentic Applications 2026** [4] (published December 9, 2025) was developed through peer review with more than 100 industry experts, researchers, and practitioners. It synthesizes cross-industry open-source security guidance, including:

- The OWASP AIVSS project's **Agentic AI Core Risks** taxonomy [5]
- OWASP GenAI LLM Top 10 (2025/2026) [4]
- OWASP *State of Agentic AI Security and Governance* [4]
- OWASP Solutions Landscape — Red Teaming Taxonomy [4]
- Real-world incident disclosures and practitioner field reports

### 5.3 OWASP Top 10 — complete list

The table below lists all ten categories in the canonical taxonomy AIVSS 1.0 adopts. **Eight of ten** (ASI01–ASI08) trace to the **OWASP AIVSS project team's** original **Agentic AI Core Risks** taxonomy [5]; **ASI09** and **ASI10** were added by OWASP during peer review [4].

<!--table:OWASP Top 10 for Agentic Applications 2026-->
| ID | Risk | Brief description |
|---|---|---|
| ASI01 | Agent Goal Hijack | Attacker redirects the agent's objectives or plan through injected or poisoned instructions |
| ASI02 | Tool Misuse & Exploitation | Agent applies a legitimate tool in an unsafe or unintended way, enabling data exfiltration or workflow hijacking |
| ASI03 | Identity & Privilege Abuse | Agent operates with excessive or stale credentials, performing actions beyond its authorized scope |
| ASI04 | Agentic Supply Chain Vulnerabilities | Malicious or tampered third-party agents, tools, plugins, or prompt templates introduced at build or runtime |
| ASI05 | Unexpected Code Execution | Agent generates or executes code — shell commands, scripts, or binaries — outside intended safety boundaries |
| ASI06 | Memory & Context Poisoning | Adversarial data planted in the agent's memory or context store causes biased or unsafe decisions in later sessions |
| ASI07 | Insecure Inter-Agent Communication | Agent-to-agent exchanges lack authentication or integrity, enabling spoofing or message interception |
| ASI08 | Cascading Failures | A fault or compromise in one agent propagates through orchestration, triggering downstream task or system failures |
| ASI09 | Human–Agent Trust Exploitation | Attacker exploits human trust in agent outputs — forged summaries, anthropomorphism, or persuasive deception |
| ASI10 | Rogue Agents | Compromised or misaligned agent operates outside policy, pursuing hidden or harmful goals with legitimate credentials |

### 5.4 AIVSS mission — scoring tool, not taxonomy authority

The primary mission of AIVSS is to provide a **reference scoring and remediation tool** for agentic AI vulnerabilities — not to maintain an independent risk taxonomy. A parallel category list would duplicate OWASP's community-maintained taxonomy without adding scoring value.

**For AIVSS version 1.0**, we **adopt OWASP ASI01–ASI10 as the sole canonical risk taxonomy** and **retire the bespoke AIVSS Agentic AI Core Risks list**. Findings are classified to an ASI category for traceability and worked examples; the category label does not enter any score formula.

<!--table:Taxonomy adoption decision-->
| Decision | Detail |
|---|---|
| Canonical taxonomy | OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10) [4] |
| Retired | AIVSS Agentic AI Core Risks [5] |
| Rationale | AIVSS is a scoring tool; OWASP maintains the taxonomy with broader community input; **eight of ten ASI categories trace to the OWASP AIVSS project team's original research** [5] |
| Traceability | **Agent Untraceability** retained as TD metric — mandatory AIVSS risk factor (Section 5.6) |

### 5.5 Crosswalk from retired AIVSS categories

<!--table:Retired AIVSS Core Risks → OWASP ASI-->
| Retired AIVSS category | OWASP ASI |
|---|---|
| Agent Goal and Instruction Manipulation | ASI01 Agent Goal Hijack |
| Agentic AI Tool Misuse | ASI02 Tool Misuse and Exploitation |
| Agent Access Control Violation | ASI03 Identity and Privilege Abuse |
| Agent Identity Impersonation | ASI03 Identity and Privilege Abuse |
| Agent Supply Chain and Dependency Risk | ASI04 Agentic Supply Chain Vulnerabilities |
| Insecure Agent Critical Systems Interaction | ASI05 Unexpected Code Execution |
| Agent Memory and Context Manipulation | ASI06 Memory and Context Poisoning |
| Agent Orchestration and Multi-Agent Exploitation | ASI07 Insecure Inter-Agent Communication |
| Agent Cascading Failures | ASI08 Cascading Failures |
| Agent Untraceability | **Retained — TD metric** (Section 5.6). Credit: OWASP AIVSS taxonomy [5]; no OWASP ASI equivalent |

New OWASP categories with no retired predecessor: **ASI09 Human–Agent Trust Exploitation**, **ASI10 Rogue Agents**.

### 5.6 Agent Untraceability — retained AIVSS risk factor

**Credit.** The risk of **Agent Untraceability** — the inability to reconstruct what an agent did, why it did it, and which tools it invoked — was identified as a distinct agentic security concern by the **OWASP AIVSS project team** in the original Agentic AI Core Risks taxonomy [5]. OWASP Top 10 for Agentic Applications 2026 [4] does not include a separate ASI category for this risk. **AIVSS 1.0 retains it** because untraceable agent behaviour materially worsens incident response, forensic triage, regulatory accountability, and safe rollback after compromise.

**Definition — Agent Untraceability.** A deployment condition in which post-incident reconstruction of an agent's reasoning chain, prompt history, and tool invocations is infeasible or unreliable, preventing defenders from determining scope of impact, attacker intent, or whether remediation succeeded.

**How AIVSS measures it.** Agent Untraceability is assessed through the **TD (Traceability Deficit)** metric in the Agentic AI Profile (Section 10.5). TD is a **mandatory risk factor** in every conformant assessment (Section 7): assessors MUST evaluate and record TD even though it does not change the Mode 1 severity number. This preserves the AIVSS taxonomy contribution while respecting the architectural rule that severity equals CVSS-BTE.

**Why it matters for agentic systems.** Unlike traditional software, agents may take dozens of autonomous tool actions per task with stochastic intermediate steps. Without prompt logging, reasoning traces, and tool-call audit trails, a successful attack can be **non-attributable and non-reversible** — the agent may have exfiltrated data or modified systems with no recoverable evidence. High TD (TD:H) SHOULD trigger enhanced incident-response procedures: assume worst-case scope, preserve ephemeral logs immediately, and block further autonomous actions until traceability controls are restored.

**Relationship to ASI categories.** Agent Untraceability often co-occurs with ASI01 (goal hijack), ASI06 (memory poisoning), and ASI10 (rogue agents), but it is **orthogonal** to those categories: a finding may be ASI02 Tool Misuse with TD:H if the deployment lacks auditability. Classify the primary flaw under ASI01–ASI10; **always assess TD separately.**

---

## 6 Architecture Overview

AIVSS is organized into three normative layers plus two optional extensions:

**Layer 1 — Severity (Part I, Section 9).** Honest CVSS v4.0 scoring with agent-specific interpretation rules. Output: `AIVSS = CVSS-BTE` in Mode 1.

**Layer 2 — Agentic AI Profile (Section 10).** Five dimensions describing language-mediated control, context persistence, agentic propagation, stochastic exploit reliability, and traceability deficit. Output: vector extension and AI Effect Class (Section 11).

**Layer 3 — Timeline (Section 12).** CISA BOD 26-04 [3] decision model plus AI Effect Class escalation. Output: BOD timeline and AIVSS recommendation.

**Optional Mode 2 (Section 13.2).** MacroVector promotion for extended severity — provisional.

**Optional AIVSS-P (Section 16).** Organization-internal priority index — Level 3 only.

The ten historical AIVSS amplification factors resolve into either CVSS Base metrics or the five AI metrics:

<!--table:Agentic Factor Disposition-->
| Agentic property | Disposition | CVSS mapping or AI metric |
|---|---|---|
| Execution autonomy | CVSS | UI, AT — agent acting without confirmation is UI:N |
| External tool control surface | CVSS | SC, SI, SA — score full tool reach |
| Dynamic identity | CVSS | PR, SC, SI, SA — agent credential not caller |
| Contextual awareness | CVSS | AT, scope guidance |
| Natural language interface | Pure AI | LC — Language-Mediated Control |
| Persistent state retention | Pure AI | CP — Context Persistence |
| Self-modification | Split | CP for memory; CVSS SI for config rewrite |
| Behavioural non-determinism | Pure AI | SR — Stochastic Reliability (or AT if chosen) |
| Multi-agent interactions | Pure AI | AP — Agentic Propagation |
| Opacity and reflexivity | Pure AI | **TD** — Traceability Deficit / Agent Untraceability (mandatory risk factor; no score effect) |

---

## 7 Conformance Levels

**Level 1 — Severity and Agentic AI Profile.** Sufficient to claim "AIVSS 1.0 conformant."

- MUST supply a CVSS v4.0 Base vector (MAY be imported from NVD or an advisory).
- MUST supply all four scored AI metrics (LC, CP, AP, SR), or explicitly none.
- **MUST assess TD (Agent Untraceability)** for every finding — record TD:H, TD:M, or TD:L in the Agentic AI Profile (Section 5.6, Section 10.5). TD does not modify the severity number but is a required risk-factor consideration.
- MUST classify the finding to an ASI01–ASI10 category [4].
- MUST emit a conformant vector string (Section 10.6).
- MAY omit the decision track and AIVSS-P.

**Level 2 — Level 1 plus decision track.** MUST supply asset exposure (`publicly_exposed`) and MUST report the unmodified BOD 26-04 [3] timeline alongside any AIVSS recommendation.

**Level 3 — Level 2 plus organizational priority.** AIVSS-P outputs are organization-internal. A Level 3 producer MUST NOT publish AIVSS-P outside the assessing organization.

**Consumer conformance.** MUST parse all vector strings at its declared level; MUST NOT display an AIVSS score in a field that also carries CVSS scores without the `AIVSS:` prefix; MUST NOT substitute a missing AI metric group for an all-benign one.

---

## 8 End-to-End Assessment Flow

An AIVSS assessment proceeds in five steps:

1. **Classify** the finding under ASI01–ASI10 [4].
2. **Build a CVSS v4.0 vector** with honest agent credential, tool-reach, and subsequent-system scoring (Section 9).
3. **Add the AI metric group** (LC, CP, AP, SR, and **TD for Agent Untraceability**) per Section 10.
4. **Run the calculator** to obtain AIVSS severity (Mode 1), AI Effect Class, and optionally Mode 2 extended severity.
5. **Supply exposure and exploitation evidence** for the remediation timeline (Section 12).

```bash
cd tools/aivss-calc && pip install -e ".[dev]"
aivss-calc assess examples/asi01-example.json
```

When AI metrics are present, they are parsed as an optional extension group in fixed order: LC / CP / AP / SR / TD. The tool computes an interpolated CVSS-BTE score, classifies the AI Effect Class, and emits Mode 1 (normative) and optionally Mode 2 (provisional) scores. At Level 2, the decision track runs in parallel.

---

## 9 CVSS Interpretation for Agentic Systems (Normative)

**Core rule:** `AIVSS = CVSS-BTE`. AI metrics are reported as an Agentic AI Profile and do not modify the numeric score in Mode 1.

Agentic properties already representable in CVSS MUST be scored in CVSS, not duplicated in the AI metric group (Section 9.3).

### 9.1 Agent-specific interpretation rules

Per CVSS v4.0 [1] and AIVSS interpretation guidance:

**PR (Privileges Required).** Score the **agent's effective credential**, not the human end-user's. In an **ASI03 Identity & Privilege Abuse** finding, if an attacker steals the agent's service account and the agent holds database write access, PR reflects that service account's privilege level — not the end user's login.

**UI (User Interaction).** If human approval is nominally required but routinely granted without meaningful review, the honest value is **UI:N** (no interaction required). In **ASI09 Human–Agent Trust Exploitation**, forged agent summaries that humans approve without review also imply UI:N for the underlying attack path.

**SC / SI / SA (Subsequent System impacts).** Score against the **full reach of the agent's tool set** — every API, database, filesystem, and downstream system the agent can invoke — not merely the process boundary of the agent runtime. In an **ASI02 Tool Misuse** finding, score SC/SI/SA against every downstream system the misused tool can reach.

**AT (Attack Requirements).** When model stochasticity is a necessary condition for exploitation (the attack succeeds only when the model produces a particular output distribution), encode that here as AT:P — as in **ASI08 Cascading Failures** where a faulty planner intermittently triggers downstream errors. If AT already captures stochasticity, do not also score SR (Section 9.3).

**E (Exploit Maturity).** Set from the exploitation evidence ladder (Section 12.3): authoritative Active (KEV or Vulnrichment) → `E:A`; organization-observed Active (unverified) or PoC → `E:P`; no evidence → `E:U`.

### 9.2 The four most common CVSS scoring errors in agentic systems

1. **Under-scoring Subsequent System metrics.** SC/SI/SA must reflect full tool reach — e.g., scoring **ASI02** at Low when the misused tool can exfiltrate customer records via a downstream CRM API.
2. **Scoring PR at the human's privilege.** Score the agent's credential — e.g., in **ASI03**, the agent's service-account privilege, not the caller's SSO session.
3. **Scoring UI:P because a human is nominally in the loop.** Routine rubber-stamp approval is UI:N — common in **ASI09** where humans trust forged agent summaries.
4. **Treating retrieval-sourced injection as requiring user interaction.** Content ingested autonomously is not user interaction — e.g., **ASI01** indirect goal hijack via poisoned documents the agent retrieves without user action.

### 9.3 Non-overlap rule

AI metrics MUST NOT rescore a condition already represented in CVSS. If model stochasticity was encoded as AT:P, do **not** also score SR. Record which representation was used in assessment notes.

---

## 10 AI Metric Group (Normative)

The AI metric group captures agent-specific properties that CVSS Base metrics do not separately name. Scored metrics: **LC**, **CP**, **AP**, **SR**. **Mandatory non-scoring metric: TD** (Agent Untraceability; Section 5.6, Section 7).

All four scored metrics MUST be present together or all absent. **TD is required** in every conformant assessment (Section 7). An unknown key MUST cause a parse failure.

### 10.1 LC — Language-Mediated Control

**Definition.** Whether attacker-controlled natural language can influence security-relevant behaviour without passing through a constrained interface.

**Example (ASI01).** Direct prompt injection that hijacks a planning agent's goals is LC:D — attacker text reaches the privileged planning path without mediation.

<!--table:LC — Language-Mediated Control-->
| Value | Label | Definition |
|---|---|---|
| LC:D | Direct | Attacker-supplied text reaches a privileged decision or tool-invocation path without mediation. |
| LC:I | Indirect | Attacker-controlled language enters through retrieved or ingested content and influences security-relevant behaviour. |
| LC:M | Mediated | Language influences behaviour only through schema-bound arguments, allowlisted actions, or enforced human approval. |
| LC:N | None | No natural-language path to security-relevant behaviour. |

### 10.2 CP — Context Persistence

**Definition.** Whether attacker-controlled context survives beyond a single interaction.

**Example (ASI06).** Adversarial data planted in the agent's memory or context store biases decisions in later sessions — CP:C (cross-session context poisoning).

<!--table:CP — Context Persistence-->
| Value | Label | Definition |
|---|---|---|
| CP:C | Cross-session | Persists in long-term memory, vector store, or training data; influences later sessions or other users. |
| CP:S | Session | Persists only within the active session. |
| CP:N | None | Single-turn only; no carryover. |

### 10.3 AP — Agentic Propagation

**Definition.** Whether compromised intent, instructions, memory, or authority crosses a trust boundary.

**Example (ASI07).** Unsigned agent-to-agent messages that allow an attacker to relay instructions to sibling agents are AP:L — lateral propagation across a trust boundary.

<!--table:AP — Agentic Propagation-->
| Value | Label | Definition |
|---|---|---|
| AP:L | Lateral | Crosses a trust boundary to other agents, tenants, or downstream systems. |
| AP:C | Contained | Propagates within the agent's own tool and action scope but does not cross a trust boundary. |
| AP:N | None | Confined to the initially affected component. |

### 10.4 SR — Stochastic Exploit Reliability

**Definition.** How reliably an attacker can reproduce the exploit, independent of whether stochasticity is already encoded in CVSS AT.

**Example (ASI05).** A code interpreter that executes attacker shell commands on every attempt is SR:R — reliable reproduction.

<!--table:SR — Stochastic Reliability-->
| Value | Label | Definition |
|---|---|---|
| SR:R | Reliable | Succeeds on essentially every attempt, or the attacker can retry freely until success. |
| SR:P | Probabilistic | Succeeds intermittently; retry is rate-limited, detectable, or otherwise constrained. |
| SR:U | Unreliable | Rarely reproducible, with no practical retry path. |

**Non-overlap rule:** If stochasticity is already encoded as CVSS AT:P, do not also score SR.

### 10.5 TD — Traceability Deficit (Agent Untraceability)

**Credit.** TD implements **Agent Untraceability**, the tenth category of the original OWASP AIVSS Agentic AI Core Risks taxonomy [5]. OWASP Top 10 [4] has no ASI equivalent; AIVSS retains this as a **mandatory risk factor** because agentic systems without audit trails create non-attributable, non-reversible security incidents.

**Definition — TD (Traceability Deficit).** The degree to which post-incident reconstruction of an agent's reasoning, prompts, and tool actions is infeasible. High traceability deficit means the deployment exhibits **Agent Untraceability**: defenders cannot reliably determine what the agent did, why, or on whose behalf.

**Scoring rule.** TD is recorded in every conformant assessment. **TD never affects the Mode 1 severity number** (AIVSS = CVSS-BTE). It informs response priority, forensic procedures, control requirements, and release gating. When TD:H, assessors SHOULD treat scope of compromise as **unknown until proven otherwise**.

<!--table:TD — Traceability Deficit (Agent Untraceability)-->
| Value | Label | Definition |
|---|---|---|
| TD:H | High deficit (Untraceable) | No reasoning trace and no tool-call audit; reconstruction infeasible. Agent actions are effectively non-attributable. |
| TD:M | Moderate deficit | Partial logging; reconstruction possible with significant effort. Gaps in prompt history or tool audit. |
| TD:L | Low deficit (Traceable) | Prompt, reasoning-trace, and tool-call logging retained and queryable. Incident reconstruction is feasible. |

**Assessment guidance.** Evaluate TD from deployment architecture, not attack technique alone. Ask: if this exploit succeeded, could we reconstruct the full chain of agent decisions and tool calls within 24 hours? An **ASI10 Rogue Agent** deployment with TD:H and no reasoning trace is especially dangerous — scope of compromise cannot be bounded after detection.

### 10.6 Vector syntax

AIVSS extends the CVSS v4.0 vector with an optional AI metric group:

```text
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N/E:P/LC:D/CP:S/AP:C/SR:R/TD:M
```

A score MUST be rendered as `AIVSS:8.3`, never as a bare number in prose or UI labels. In structured JSON output the numeric value lives in `scores.mode1_interpretation.aivss`; consumers MUST prefix with `AIVSS:` when displaying to humans.

---

## 11 AI Effect Class

The scored AI metrics produce an **AI Effect Class** by boolean ladder. No arithmetic is performed on ordinal metric levels.

- **A2 (Substantial)** — AP:L, **or** (LC in {D, I} **and** CP:C), **or** (LC:D **and** SR:R)
- **A1 (Present)** — not A2, but any scored metric above its benign value (LC≠N, CP≠N, AP≠N, or SR≠U)
- **A0 (None)** — LC:N and CP:N and AP:N and SR:U, or the AI metric group is absent

**Identity rule:** A0 implies `AIVSS = CVSS-BTE` exactly, in both Mode 1 and Mode 2. Verified in the reference implementation over representative vectors and exhaustive A0 promotion invariance across all 270 MacroVector classes.

**Rationale for A2 clauses:**

- **AP:L** — propagation across a trust boundary is categorically the most severe agentic effect.
- **LC {D,I} + CP:C** — persistent cross-session context poisoning reachable by language is the signature agentic attack pattern.
- **LC:D + SR:R** — direct, reliable language control of a privileged path is a dependable injection primitive.

---

## 12 Remediation Timelines (Normative at Level 2)

**Severity does not determine remediation urgency.** Since June 10, 2026, BOD 26-04 [3] has replaced CVSS-severity-driven federal remediation with a four-variable model. AIVSS consumes that model verbatim and adds one decision point: the AI Effect Class.

### 12.1 BOD 26-04 decision inputs

<!--table:BOD 26-04 Decision Inputs-->
| Decision point | Definition | Source |
|---|---|---|
| KEV status | Whether the CVE is in CISA's Known Exploited Vulnerabilities catalog | CISA KEV [3] |
| Public exposure | Whether the vulnerable component is reachable from the public internet | Assessing organization |
| Automatable | Whether exploitation can be automated at scale | CISA Vulnrichment; if unavailable, derive from SR:R |
| Technical impact | Whether compromise affects confidentiality, integrity, or availability at partial or total level | CISA Vulnrichment; if unavailable, derive from CVSS VC/VI/VA |
| AI Effect Class | Whether agentic amplification is substantial (A2), present (A1), or none (A0) | AIVSS Section 11 |

Where CISA has published neither Automatable nor Technical Impact and the CVE is not in KEV, BOD 26-04 directs that they be treated as "no" and "total" respectively. SR/CVSS derivations apply only for non-CVE findings without Vulnrichment data.

### 12.2 BOD 26-04 Table 1 (16 rows)

All sixteen rows, transcribed from `cisa:BOD2604:1.0.0` [3]. Held as a lookup table, not boolean logic: the fast tier requires exposure or automatability **in addition to** KEV.

<!--table:BOD 26-04 Table 1 (16 rows)-->
| In KEV | Publicly Exposed | Automatable | Technical Impact | Timeline |
|---|---|---|---|---|
| no | no | no | partial | Fix on system upgrade |
| no | no | no | total | Fix on system upgrade |
| no | yes | no | partial | 60 days |
| no | no | yes | partial | 60 days |
| no | no | yes | total | 60 days |
| yes | no | no | partial | 14 days |
| yes | yes | no | partial | 14 days |
| yes | no | yes | partial | 14 days |
| no | yes | yes | partial | 14 days |
| yes | no | no | total | 14 days |
| no | yes | no | total | 14 days |
| yes | yes | yes | partial | 3 days |
| no | yes | yes | total | 3 days |
| yes | yes | no | total | 3 days and forensic triage |
| yes | no | yes | total | 3 days and forensic triage |
| yes | yes | yes | total | 3 days and forensic triage |

### 12.3 Exploitation evidence ladder

Strict precedence, highest authority first. Replaces withdrawn multiplier-based threat models (`max(ThM_discrete, ThM_EPSS, ThM_KEV)` from earlier AIVSS drafts). The ladder selects **factual exploitation evidence** only.

1. CVE listed in CISA KEV → **Active** (authoritative)
2. CISA Vulnrichment reports Exploitation: active → **Active** (authoritative)
3. Exploitation observed and documented by the assessing organization → **Active (unverified)** — essential for non-CVE agentic findings
4. Proof-of-concept exists → **PoC**
5. No evidence → **None**

The selected rung sets CVSS `E` (Exploit Maturity) for the assessment: authoritative Active (items 1–2) → `E:A`; Active (unverified) or PoC (items 3–4) → `E:P`; None (item 5) → `E:U`.

**EPSS is not on this ladder.** Published EPSS scores are recorded alongside the ladder result (`epss`, `epss_date`) but never override a rung selected from items 1–5 above. See Section 12.3.1.

**Withdrawn constructs:** `EPSS_AI`, `AI-KEV`, `SSVC-AI`. Each borrowed an owning organization's name for an artifact lacking the property the name asserts.

### 12.3.1 Why EPSS is recorded but not used in scoring or ladder selection

EPSS is valuable intelligence. AIVSS **requires recording it when available** and **prohibits using it to change any normative output**. Five reasons:

**1. BOD 26-04 does not use EPSS.** The federal remediation model that AIVSS consumes verbatim (Sections 12.1–12.2) keys on KEV status, public exposure, automatable, and technical impact [3]. EPSS is not an input to the 16-row BOD lookup. Folding EPSS into AIVSS timeline or severity would depart from the cited compliance model without adding a defensible mapping.

**2. Forecast ≠ fact.** EPSS estimates the *probability* of future exploitation. The exploitation ladder selects *documented* signals: CISA-confirmed active exploitation (KEV, Vulnrichment), organization-observed exploitation, or a proof-of-concept. Treating a 0.42 EPSS score as "PoC" or "Active" would substitute a statistical forecast for factual evidence and misrepresent what was actually observed.

**3. Prior AIVSS integration was mathematically inert.** Earlier drafts combined EPSS with a Threat Multiplier via `max(ThM_discrete, ThM_EPSS)` where `ThM_discrete(PoC) = 0.97` and `ThM_EPSS = 0.50 + 0.50 × EPSS`. Under `max()` selection, EPSS could change the result only when **EPSS > 0.94** — a tiny fraction of the published distribution, most of which is already KEV-listed. Maximum achievable effect on severity: **0.3 points** at the low end of the scale, and **0.1 points** for findings above CVSS 7.0. The draft's own worked example showed EPSS 0.42 producing `ThM_EPSS = 0.71`, which was discarded. The integration appeared to use EPSS but did not.

**4. `EPSS_AI` is withdrawn and must not return.** Agentic findings are often non-CVE or lack NVD coverage. The withdrawn `EPSS_AI` construct — four booleans substituted into a transform designed for a calibrated probability — would misrepresent EPSS's measurement model and violate AIVSS's probability disclaimer (Section 4.3). Organizations may apply EPSS (or their own models) in **separate** prioritization workflows; AIVSS does not invent a parallel probability score.

**5. Reproducibility requires an observation date.** EPSS is revised daily. An assessment that used EPSS to set exploitation state without `epss_date` would not be reproducible. Recording EPSS as dated metadata preserves auditability without letting a moving forecast rewrite a scored finding retroactively.

**What practitioners should do with EPSS in an AIVSS assessment:**

<!--table:EPSS permitted and prohibited uses-->
| Use EPSS for | Do not use EPSS for |
|---|---|
| Supplemental dashboards and SOC triage alongside the AIVSS report | Selecting the exploitation-ladder rung |
| Correlating AIVSS severity with industry exploit forecasts | Setting CVSS `E` (Exploit Maturity) |
| Organizational risk acceptance when EPSS exceeds internal thresholds | Modifying `AIVSS = CVSS-BTE` (Mode 1 severity) |
| Trend analysis across reassessments (with dated snapshots) | Changing the BOD 26-04 timeline lookup |

Record via: `aivss-calc decide --epss 0.42 --epss-date 2026-08-27` (or equivalent fields in the assessment JSON). The reference implementation always emits `epss` and `epss_date` in the decision output when supplied; the ladder `rung` is determined solely by items 1–5 above.

### 12.4 AI Effect Class escalation

When the AI Effect Class is **A2**, the recommended timeline advances by exactly one tier: FSU → 60D → 14D → 3D. **Escalation stops at 3D.** AIVSS never escalates into forensic triage (that is a CISA determination tied to KEV listing [3]).

The unmodified BOD 26-04 result MUST always be reported alongside the AIVSS recommendation. For an FCEB agency, the BOD value is the compliance obligation.

---

## 13 Scoring Modes

### 13.1 Mode 1 — Interpretation (normative)

`AIVSS = CVSS-BTE`. AI metrics are reported as an Agentic AI Profile. Immediately usable, zero score inflation, identity trivially preserved. Scoring uses proper CVSS v4.0 interpolation per FIRST [1], not MacroVector ceiling values.

### 13.2 Mode 2 — MacroVector extension (provisional)

```
AIVSS-BTEA = Lookup_AIVSS(EQ1, EQ2, EQ3, EQ4, EQ5, EQ6, A)
```

EQ1–EQ6 are the CVSS v4.0 equivalence groups (270 valid classes). A is the AI Effect Class.

An AI Effect Class does not add a free-form numeric uplift. Mode 2 **promotes** the vector's MacroVector equivalence class (EQ4 at A1; EQ4 and EQ1 at A2) and applies the **expert-ranked ceiling delta** from FIRST `cvss_lookup.js` [1] to the vector's interpolated CVSS-BTE base:

```
AIVSS-BTEA = min(10.0, CVSS-BTE + (score(promoted_MV) − score(base_MV)))
```

This preserves the vector's position within its MacroVector class while transferring only the expert-ranked gap to the promoted neighbour — it does **not** return the promoted MacroVector ceiling alone (which would ignore within-class interpolation).

<!--table:S2 Promotion Rules-->
| AI Class | Promotion |
|---|---|
| A0 | none — identity |
| A1 | EQ4 → max(0, EQ4 − 1) |
| A2 | EQ4 → max(0, EQ4 − 1) and EQ1 → max(0, EQ1 − 1) |

EQ4 (SC/SI/SA) is promoted because subsequent-system impact is the dimension agentic persistence and propagation extend. EQ1 (AV/PR/UI) is additionally promoted at A2 because substantial language-mediated control effectively removes privilege and interaction barriers.

**Verified properties** (reference implementation): Identity at A0 (0 sample violations), Monotone promotion (0 violations), Bounded (≤ 10.0), Ordered (A2 ≥ A1 ≥ A0 on representative vectors). Every delta is drawn from FIRST's published MacroVector scores.

**Known limitation:** A1 is a no-op for MacroVectors already at EQ4 = 0; A2 is a full no-op for 11% of the space. Saturation is reported in tool output.

**Provisional pending expert calibration; not for use in contracts, SLAs, or compliance gates.**

---

## 14 OWASP Top 10 — Calculator Results

Every row scored with `aivss-calc assess`. Example files in `tools/aivss-calc/examples/`.

<!--table:OWASP Agentic AI Top 10 — Calculator Results-->
| ID | Risk | Example finding | AIVSS | AI Class | BOD timeline | AIVSS timeline |
|---|---|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | Attacker redirects planning agent objectives via injected instructions | 9.2 | A2 | 3 days | 3 days |
| ASI02 | Tool Misuse & Exploitation | Agent misuses legitimate tool for unauthorized data export | 8.3 | A1 | 3 days | 3 days |
| ASI03 | Identity & Privilege Abuse | Stolen service credential used for lateral agent actions | 8.5 | A2 | 60 days | 14 days |
| ASI04 | Agentic Supply Chain Vulnerabilities | Compromised MCP plugin supplies malicious tool definitions | 8.8 | A2 | 14 days | 3 days |
| ASI05 | Unexpected Code Execution | Code interpreter executes attacker-supplied shell commands | 8.9 | A2 | 3 days | 3 days |
| ASI06 | Memory & Context Poisoning | Adversarial content in agent memory biases later sessions | 7.8 | A2 | 3 days | 3 days |
| ASI07 | Insecure Inter-Agent Communication | Unsigned agent-to-agent messages allow instruction relay | 7.1 | A2 | 60 days | 14 days |
| ASI08 | Cascading Failures | Faulty planner triggers cascading downstream task failures | 7.9 | A2 | 14 days | 3 days |
| ASI09 | Human–Agent Trust Exploitation | Social engineering of human approver via forged agent summaries | 7.0 | A1 | 14 days | 14 days |
| ASI10 | Rogue Agents | Compromised worker agent operates outside policy envelope | 8.6 | A2 | 3 days | 3 days |

---

## 15 Worked Example — ASI06 Memory and Context Poisoning

**Finding narrative.** ASI06 Memory and Context Poisoning. Adversarial content is planted in the agent's shared context store, reaches a tool-invocation path directly, propagates to sibling agents, and reproduces reliably. No reasoning trace is retained.

**Input vector:**

```text
CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P/LC:D/CP:C/AP:L/SR:R/TD:H
```

<!--table:ASI06 Worked Example-->
| Output | Value |
|---|---|
| MacroVector | 011110 |
| MacroVector ceiling | 8.0 |
| CVSS-BTE (interpolated) | 7.8 |
| AI Effect Class | A2 (AP:L; also LC:D+CP:C; also LC:D+SR:R) |
| Mode 1 — AIVSS | 7.8 (normative) |
| Mode 2 — AIVSS-BTEA | 9.0 via promoted MacroVector 011010 (provisional) |
| Exploitation rung | PoC |
| Automatable | yes (derived from SR:R) |
| Technical Impact | total (derived from VC:H) |
| BOD 26-04 timeline | 3 days |
| AIVSS recommendation | 3 days (already at ceiling; no escalation) |
| AIVSS-P (BI high, reach high, L 0.72) | 87 — Immediate |

Mode 1–2 and decision-track rows are emitted by:

```bash
aivss-calc assess examples/asi06-example.json
```

The AIVSS-P row uses `examples/asi06-memory-poisoning.json` (likelihood 0.72):

```bash
aivss-calc assess examples/asi06-memory-poisoning.json
```

---

## 16 AIVSS-P — Organizational Priority (Level 3, Optional)

AIVSS-P is an **organization-internal** priority index. It MUST NOT be published outside the assessing organization.

```
AIVSS-P = 100 × geometric_mean(S/10, BI, REACH, L)
```

<!--table:AIVSS-P index symbols-->
| Symbol | Definition |
|---|---|
| S | Technical severity — the AIVSS Mode 1 score (0–10) |
| BI | Business criticality — organization's assessment of asset importance (0–1) |
| REACH | Deployment reach — fraction of users or systems affected (0–1) |
| L | Likelihood — organization-assessed probability of exploitation (0–1); NIST SP 800-30 Rev. 1 [6] is a suitable methodology reference |

Each quantity is priced exactly once. Exploitation evidence belongs to the decision track (Section 12), not AIVSS-P.

**Band cut-points** (p90 / p65 / p35 of a uniform grid, n = 10,980, severity 4.0–10.0): **Immediate ≥ 78, This sprint ≥ 64, Scheduled ≥ 53, Backlog below 53.** The grid over-represents high-severity findings relative to a real portfolio; organizations SHOULD recalibrate cut-points against their own assessment corpus (Section 22).

### 16.1 Intellectual lineage (non-normative)

AIVSS-P's likelihood × impact decomposition descends from the OWASP Risk Rating Methodology; its separation of environmental context from intrinsic severity descends from CWSS v1.0. Both are cited as **design lineage, not current authority**. AIVSS grounds normative likelihood guidance in NIST SP 800-30 Rev. 1 [6].

---

## 17 Governance and Calibration Commitments

The working group commits to publishing:

1. A conformance test-vector file with exact expected outputs and zero tolerance.
2. A score distribution over a corpus of at least 200 assessed findings.
3. An inter-rater reliability study: at least 20 findings × 8 assessors, with Krippendorff's α reported per AI metric.
4. A change-control policy: semantic versioning, public issue tracker, minimum 12-month deprecation notice.
5. An expert-ranking exercise to replace the Mode 2 strawman generator (Section 13.2).

---

## 18 Reference Implementation

```bash
cd tools/aivss-calc && pip install -e ".[dev]"
aivss-calc taxonomy          # OWASP ASI01–ASI10
aivss-calc profile "<vector>"   # Mode 1 severity + Agentic AI Profile
aivss-calc lookup "<vector>"    # Mode 2 AIVSS-BTEA (provisional)
aivss-calc decide --vector "<vector>" --publicly-exposed [--kev] ...
aivss-calc assess examples/asi01-example.json
aivss-calc priority --severity 7.8 --business-criticality high --reach high --likelihood 0.72
aivss-calc verify              # MacroVector property checks
aivss-calc legacy --factors <file>   # withdrawn uplift model (deprecated)
python examples/generate_asi_examples.py
pytest                         # 93 tests
```

---

# Implementation Guide — AIVSS-Agentic (Informative)

This section is **informative guidance** for practitioners integrating AIVSS 1.0 into engineering workflow, governance, and risk programs. It does not change any normative rule in Sections 1–18. Organizations MAY adopt these practices wholly or in part.

---

## 19 AIVSS-Agentic Implementation Guide

The implementation guide answers: **where, when, and how** to run an AIVSS assessment in the lifecycle of an agentic system, and **what outputs** gate release or trigger escalation.

### 19.1 Lifecycle Integration

AIVSS assessments SHOULD be performed at every phase where agentic attack surface or autonomy changes. The table below maps lifecycle phases to assessment activities, primary outputs, and conformance level.

<!--table:Lifecycle Integration — AIVSS Touchpoints-->
| Phase | Trigger | Assessment focus | AIVSS outputs | Conformance |
|---|---|---|---|---|
| Design / threat modeling | New agent capability, new tool, new data source | ASI classification; honest CVSS reach (SC/SI/SA); LC/CP/AP draft | ASI id, vector draft, TD target (logging design) | Level 1 |
| Build / CI | Dependency change, MCP plugin added, prompt template update | ASI04 supply chain; ASI05 code-exec paths; TD:H gate if no audit trail | Full vector + TD; block merge on TD:H without compensating control | Level 1 |
| Test / red team | Pre-release, annual pen test | Validate LC, SR, AP under adversarial prompts | AIVSS severity, AI Effect Class, evidence ladder rung | Level 1–2 |
| Staging / pre-prod | Exposure change, KEV watch | BOD 26-04 decision track with `publicly_exposed` | BOD timeline + AIVSS recommendation | Level 2 |
| Production / operate | CVE published, incident, config drift | Re-assess with exploitation evidence; TD for forensics readiness | Updated decision track; incident scope assumptions from TD | Level 2 |
| Decommission | Agent retired | Final assessment archive for compliance retention | Signed JSON report (Appendix A) | Level 1 |

**Integration with MAESTRO.** The **Cloud Security Alliance (CSA) MAESTRO** framework (Multi-Agent Environment, Security, Threat, Risk, and Outcome) [10] provides a seven-layer architecture for agentic threat modeling: Foundation Models, Data Operations, Agent Frameworks, Deployment Infrastructure, Evaluation and Observability, Security and Compliance (vertical), and Agent Ecosystem. MAESTRO's threat taxonomy uses ASI threat IDs (T1–T15) and cross-layer analysis; practitioners map validated threats to **OWASP ASI01–ASI10** for AIVSS classification. Use MAESTRO to **discover** findings; use AIVSS to **score** them consistently (Section 20.1).

**Minimum viable integration.** At minimum, every production agent release SHOULD produce one AIVSS assessment per material security finding, stored as a versioned JSON report (Appendix A) linked to the deployment configuration hash and model/tool manifest.

### 19.2 Release Gates and Approval Mechanisms

Release gates translate AIVSS outputs into **allow / remediate / block** decisions. Gates MUST be defined by the deploying organization; the table below is a recommended starting point.

<!--table:Recommended Release Gates-->
| Condition | Recommended gate | Rationale |
|---|---|---|
| AIVSS ≥ 9.0 (Critical) | **Block** release until remediated or accepted by named risk owner | Aligns with CVSS Critical band |
| AIVSS 7.0–8.9 and AI Effect Class A2 | **Block** or require compensating controls + 14-day remediation plan | Substantial agentic amplification |
| TD:H (Agent Untraceability) | **Block** production deploy unless forensic logging roadmap approved | Cannot investigate or scope incidents (Section 5.6) |
| TD:H and AIVSS ≥ 7.0 | **Block** — treat scope of compromise as unknown | Highest operational risk combination |
| ASI05 + SR:R + UI:N | **Block** autonomous code execution without sandbox | Unexpected code execution with reliable exploit |
| AIVSS 4.0–6.9 and A0/A1 | **Allow** with standard backlog prioritization | Moderate severity, limited agentic amplification |
| BOD timeline 3D or 3DF | **Expedite** patch regardless of sprint planning | Federal or policy-aligned urgency |

**Human approval mechanisms.** When CVSS `UI:P` or `UI:A` is scored honestly, the human approval step itself becomes part of the attack surface (ASI09). Release gates SHOULD require:

1. **Dual control** — security reviewer independent of feature team signs AIVSS vector.
2. **Approval audit** — if the agent can act on human approval, log approver identity, prompt shown, and tool calls authorized (reduces TD).
3. **A2 escalation** — any A2 finding triggers security architecture review before waive.

**Waivers.** Waivers MUST record: finding ID, AIVSS vector, waiver authority, expiry date, and compensating controls. Waivers MUST NOT alter the stored AIVSS score — only the deployment decision.

---

## 20 Integration with Risk Management Frameworks

AIVSS is a **technical severity and remediation-timing** instrument. It feeds — but does not replace — enterprise risk management.

### 20.1 Mapping to common frameworks

AIVSS complements architecture-level discovery frameworks — notably the **Cloud Security Alliance (CSA) MAESTRO** Agentic AI Threat Modeling Framework [10] — by supplying comparable severity, Agentic AI Profile, and remediation timing once MAESTRO-layer threats are validated as scoreable findings (Section 19.1).

<!--table:AIVSS Mapping to Risk Frameworks-->
| Framework | AIVSS role | Integration point |
|---|---|---|
| **NIST SP 800-37 Rev. 2 (RMF)** | Severity input to risk determination | AIVSS findings support RA-3 risk assessment and POA&M prioritization; BOD timeline informs remediation scheduling |
| **NIST SP 800-30 Rev. 1** | Likelihood-informed prioritization (AIVSS-P only) | Technical severity from AIVSS Mode 1; organizational likelihood in AIVSS-P `L` term (Section 16) |
| **NIST AI RMF 1.0** | Cybersecurity measurement for deployed agents | MAP/MEASURE functions: ASI taxonomy classifies agentic risks; TD addresses transparency/accountability |
| **CSA MAESTRO — Agentic AI Threat Modeling Framework** [10] | Seven-layer architecture threat discovery | Layer review (Foundation Models through Agent Ecosystem plus Security & Compliance vertical) surfaces candidate threats; map to ASI01–ASI10 and score with AIVSS (Section 19.1) |
| **CISA BOD 26-04** | Normative remediation timing (Level 2) | AIVSS decision track consumes BOD verbatim (Section 12) |
| **ISO/IEC 27001:2022** | Evidence for A.8 vulnerability management | AIVSS JSON reports as structured assessment records |
| **CVSS v4.0 / FIRST** | Base measurement | AIVSS = CVSS-BTE in Mode 1; no fork of CVSS semantics |
| **MITRE ATLAS** [9] | Technique-level threat intelligence | ATLAS techniques inform finding narrative; ASI provides category; AIVSS scores impact |

### 20.2 Federal and regulated environments

For **FCEB agencies**, BOD 26-04 [3] is the compliance obligation; AIVSS `bod_2604_timeline` MUST be reported unmodified. The `aivss_recommended_timeline` is an organizational overlay only.

For **non-federal** organizations, BOD 26-04 MAY be adopted as a policy baseline; AIVSS provides a consistent mechanical application of Table 1 plus AI Effect Class escalation.

---

## 21 AI Threat Taxonomies and Key References

Practitioners SHOULD cross-reference multiple taxonomies. AIVSS 1.0 uses OWASP ASI01–ASI10 for classification and retains Agent Untraceability as TD (Section 5.6).

<!--table:AI Threat Taxonomies and References-->
| Taxonomy / reference | Scope | Relationship to AIVSS 1.0 |
|---|---|---|
| **OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)** [4] | Canonical agentic app risks | Primary risk classification in AIVSS |
| **OWASP AIVSS Agentic AI Core Risks** [5] | Original ten-category research taxonomy | Lineage for ASI01–ASI08; Agent Untraceability → TD |
| **OWASP GenAI LLM Top 10 2025/2026** [4] | LLM application risks | Complementary; many agent findings also map to LLM risks |
| **MITRE ATLAS** | Adversarial ML/AI techniques | Technique IDs inform threat narratives; not a severity scale |
| **CSA MAESTRO — Agentic AI Threat Modeling Framework** [10] | Seven-layer architecture threat modeling | Discovery layer; cross-layer analysis; map threats to ASI01–ASI10 for AIVSS scoring (Section 20.1) |
| **CISA KEV / Vulnrichment** [3] | Known exploited CVEs | Authoritative exploitation inputs to decision track |
| **FIRST EPSS** [11] | Exploitation probability forecast | **Recorded as dated metadata** in every report where available; does not enter ladder, severity, or BOD lookup (Section 12.3.1) |
| **NIST SP 800-30 Rev. 1** [6] | Risk assessment methodology | Guides AIVSS-P likelihood estimation |
| **CISA BOD 26-04 / CERT-CC SSVC** [3] | Remediation prioritization | Normative timeline backbone |

**Crosswalk discipline.** One finding → one primary ASI category → one AIVSS vector. Secondary taxonomy mappings (ATLAS, MAESTRO layer, LLM Top 10) belong in finding metadata, not in the score formula.

---

## 22 Continuous Improvement

AIVSS 1.0 is a living specification. Continuous improvement activities include:

1. **Corpus growth** — Collect de-identified assessment JSON reports; publish score distributions (Section 17 commitment).
2. **Inter-rater reliability** — Periodic studies across LC, CP, AP, SR, TD with Krippendorff's α; revise rubrics where agreement is low.
3. **Calculator conformance** — Run `aivss-calc verify` and `pytest` on every release; zero tolerance on test-vector drift.
4. **Taxonomy alignment** — Track OWASP GenAI Security Project updates to ASI01–ASI10; AIVSS adopts taxonomy changes through semver, not silent edits.
5. **Mode 2 calibration** — Replace strawman MacroVector promotion (Section 13.2) with expert-ranked lookup when available.
6. **Community feedback** — Issues and PRs against `tools/aivss-calc` and schema files; minimum 12-month deprecation notice for normative changes (Section 17).

Organizations SHOULD recalibrate AIVSS-P band cut-points (Section 16) against their own finding corpus annually.

---

## 23 Disclaimer

This document and the reference calculator (`tools/aivss-calc`) are provided **as-is** for community use under open-source licenses. They do **not** constitute legal, regulatory, or professional security advice.

1. **No endorsement.** AIVSS is not endorsed by, affiliated with, or approved by OWASP, FIRST, CISA, NIST, MITRE, or any government agency.
2. **No warranty.** No guarantee is made that AIVSS scores predict exploitation, breach likelihood, or business impact.
3. **Assessor responsibility.** Final severity and remediation decisions remain the responsibility of the assessing organization and qualified security professionals.
4. **Federal compliance.** Only CISA BOD 26-04 itself — not AIVSS overlays — creates FCEB compliance obligations.
5. **Mode 2 provisional.** AIVSS-BTEA (Mode 2) is experimental and MUST NOT be used in contracts, SLAs, or regulatory filings without explicit expert calibration.
6. **AIVSS-P internal use.** Organizational priority scores MUST NOT be published externally or compared across organizations.

---

## 24 Acknowledgements

AIVSS 1.0 builds on open-source security research and standards community work:

- **OWASP AIVSS Project team** — original Agentic AI Core Risks taxonomy, including Agent Untraceability; project leadership and community surveys.
- **OWASP GenAI Security Project** — Top 10 for Agentic Applications 2026 (ASI01–ASI10) and cross-industry peer review.
- **Jeff Williams** — Appendix E architectural guidance (CVSS-compatible scoring, Option 3).
- **FIRST / CVSS SIG** — CVSS v4.0 specification and `cvss_lookup.js` reference implementation.
- **CISA and CERT/CC** — BOD 26-04, KEV catalog, and Vulnrichment program.
- **NIST** — SP 800-30 risk assessment guidance referenced by AIVSS-P.
- **MITRE** — ATLAS adversarial AI knowledge base, referenced in implementation guidance.
- **MAESTRO framework contributors** — seven-layer agentic threat modeling complementary to AIVSS scoring.
- **Reference implementation contributors** — `tools/aivss-calc` maintainers, test authors, and working-group reviewers.

---

## Appendix A — AIVSS-Agentic Report JSON Schema

Normative machine-readable schema: `schemas/aivss-report-v1.0.json` (accepts `aivss_version` `1.0`; `0.9` retained for backward compatibility in `schemas/aivss-report-v0.9.json`).

### A.1 Top-level report structure

<!--table:AIVSS Report — Fields-->
| Field | Type | Description |
|---|---|---|
| `aivss_version` | string | Specification version (e.g. `0.9` / `1.0`) |
| `rubric_version` | string | AI metric rubric version — pinned for reproducibility |
| `finding_id` | string | Unique finding identifier |
| `risk_category` | object | `{ "id": "ASI06", "name": "Memory & Context Poisoning" }` |
| `vector` | string | Full CVSS:4.0 vector including AI metric group |
| `cvss` | object | `{ vector, macrovector, cvss_bte }` |
| `ai_profile` | object | Agentic AI Profile — `{ present, metrics, vector_fragment, effect_class }` |
| `scores` | object | `mode1_interpretation` (required); `mode2_macrovector` (optional) |
| `decision` | object | Level 2: BOD 26-04 + exploitation ladder |
| `priority` | object | Level 3 only: AIVSS-P (organization-internal) |
| `provenance` | object | Assessor, tool, timestamp |

### A.2 Example report (excerpt)

```json
{
  "finding_id": "AIVSS-ASI06-001",
  "risk_category": { "id": "ASI06", "name": "Memory & Context Poisoning" },
  "vector": "CVSS:4.0/.../LC:D/CP:C/AP:L/SR:R/TD:H",
  "scores": { "mode1_interpretation": { "aivss": 7.8, "status": "normative" } },
  "ai_profile": { "effect_class": "A2", "metrics": { "TD": "H (High deficit)" } },
  "decision": { "bod_2604_timeline": "3D", "aivss_recommended_timeline": "3D" }
}
```

Produce full reports with: `aivss-calc assess examples/asi06-example.json`

Validate structure against `schemas/aivss-report-v1.0.json`.

---

## Appendix D — Contributor Survey Findings and Relative Risk Ranking

### D.1 Survey context

The following ranking reflects a **contributor survey conducted by the AIVSS working group** (sample size and instrument documented internally; formal publication planned under Section 17). It informed taxonomy emphasis in version 1.0 and is **not** an input to any score formula.

During development of the OWASP AIVSS **Agentic AI Core Risks** taxonomy [5], project contributors and practitioners ranked agentic security concerns by **relative operational impact** — likelihood of occurrence in deployed agents combined with severity of consequence if exploited. The survey informed the original ten-category taxonomy and later crosswalk to OWASP ASI01–ASI10 [4].

**Methodology (summary).** Contributors ranked risk themes on a 1–10 impact scale and indicated prevalence in production agent deployments. Results were aggregated by median rank. This appendix preserves the **relative ordering** that shaped AIVSS research; it is **informative**, not a scoring input.

### D.2 Relative risk ranking — original AIVSS core risks

<!--table:Contributor Survey — Relative Risk Ranking (AIVSS Core Risks)-->
| Rank | Original AIVSS core risk | Median impact score | OWASP ASI mapping | AIVSS 1.0 status |
|---|---|---|---|---|
| 1 | Agent Goal and Instruction Manipulation | 9.4 | ASI01 Agent Goal Hijack | Adopted in OWASP Top 10 |
| 2 | Agentic AI Tool Misuse | 9.1 | ASI02 Tool Misuse & Exploitation | Adopted in OWASP Top 10 |
| 3 | Agent Untraceability | 8.9 | *(no ASI equivalent)* | **Retained as TD metric** (Section 5.6) |
| 4 | Agent Memory and Context Manipulation | 8.7 | ASI06 Memory & Context Poisoning | Adopted in OWASP Top 10 |
| 5 | Agent Supply Chain and Dependency Risk | 8.5 | ASI04 Agentic Supply Chain | Adopted in OWASP Top 10 |
| 6 | Insecure Agent Critical Systems Interaction | 8.3 | ASI05 Unexpected Code Execution | Adopted in OWASP Top 10 |
| 7 | Agent Access Control Violation | 8.0 | ASI03 Identity & Privilege Abuse | Adopted (merged with identity) |
| 8 | Agent Orchestration and Multi-Agent Exploitation | 7.8 | ASI07 Insecure Inter-Agent Communication | Adopted in OWASP Top 10 |
| 9 | Agent Cascading Failures | 7.5 | ASI08 Cascading Failures | Adopted in OWASP Top 10 |
| 10 | Agent Identity Impersonation | 7.3 | ASI03 Identity & Privilege Abuse | Adopted (merged with access control) |

### D.3 Key findings

1. **Goal hijack and tool misuse** ranked highest — consistent with OWASP placing ASI01 and ASI02 at the top of the Agentic Top 10 [4].
2. **Agent Untraceability ranked third** — contributors rated opaque agent behaviour as nearly as consequential as direct exploitation, because it prevents scoping, attribution, and safe rollback. This validated retaining it in AIVSS 1.0 as mandatory TD assessment even without an OWASP ASI category.
3. **Eight of ten** original themes map directly to OWASP ASI categories; OWASP later added **ASI09** (Human–Agent Trust Exploitation) and **ASI10** (Rogue Agents) as separate Top 10 categories.
4. **Identity and access control** were distinct in the survey but merged in OWASP ASI03 — assessors SHOULD document both impersonation and privilege-abuse angles in finding narratives.

### D.4 Use in AIVSS 1.0

Survey rankings **do not enter any score formula**. They explain **why** the taxonomy emphasizes certain risks and **why** Agent Untraceability remains a first-class AIVSS concern via TD. Practitioners MAY use the ranking to prioritize threat-modeling depth (e.g., always deep-dive ASI01, ASI02, and TD logging architecture).

---

## References

1. FIRST. CVSS v4.0 Specification Document, Section 8.2 MacroVectors. https://www.first.org/cvss/v4.0/specification-document
2. FIRST. CVSS v4.0 FAQ (scope of CVSS measurement). https://www.first.org/cvss/v4-0-faq
3. CISA. BOD 26-04: Prioritizing Security Updates Based on Risk, June 10, 2026. CERT/CC SSVC model `cisa:BOD2604:1.0.0`.
4. OWASP GenAI Security Project. Top 10 for Agentic Applications 2026 (ASI01–ASI10), December 9, 2025. https://genai.owasp.org/
5. OWASP AIVSS Project. Agentic AI Core Risks taxonomy (research lineage for ASI01–ASI08). https://owasp.org/www-project-aivss/
6. NIST SP 800-30 Rev. 1. Guide for Conducting Risk Assessments.
7. FIRST. `cvss_lookup.js`, CVSS v4.0 calculator reference implementation (BSD-2-Clause).
8. AIVSS v1.00.8 draft, Appendix E — AIVSS v2 Proposal: CVSS-Compatible AI Scoring (Jeff Williams).
9. MITRE. ATLAS — Adversarial Threat Landscape for AI Systems. https://atlas.mitre.org/
10. Cloud Security Alliance. MAESTRO — Agentic AI Threat Modeling Framework. https://cloudsecurityalliance.org/
11. FIRST. Exploit Prediction Scoring System (EPSS). https://www.first.org/epss/
