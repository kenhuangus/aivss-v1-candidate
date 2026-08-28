# CVSS v4.0 and AIVSS Boundaries

AIVSS uses the
[CVSS v4.0 Extensions Framework](https://www.first.org/cvss/v4.0/user-guide).
The CVSS vector and AIVSS extension vector are listed separately:

```text
CVSS:4.0/AV:.../SA:...
AIVSS:2.0/LC:.../CP:.../AP:.../SR:.../EX:.../PT:.../CA:.../TD:...
```

AIVSS does not add metrics to a CVSS metric group or change CVSS definitions,
formulas, constants, ordering, or scores.

## Separation rules

| AIVSS metric | Related CVSS or CISA concept | Boundary |
|---|---|---|
| LC | CVSS UI | UI records required human participation. LC records how attacker-controlled language reaches security-relevant agent logic. |
| CP | No direct CVSS equivalent | CP records behavioral persistence of attacker-controlled context or memory, not data-retention policy in general. |
| AP | CVSS SC/SI/SA | AP records whether intent, authority, or state propagates across a trust boundary. SC/SI/SA record the resulting impact to subsequent systems. |
| SR | CVSS AC/E; CISA Automatable | SR records confidence-bounded exploit reliability under the full enforced attacker budget. AC records attack complexity, E records exploit maturity, and Automatable asks whether all exploitation steps can be automated. None may be inferred from another. |
| EX | CVSS AV/AT and SC/SI/SA | EX records whether reachable extension identity, operations, arguments, credentials, and authorization are independently constrained. CVSS records access, prerequisites, and realized impact. |
| PT | CVSS PR/AT | PT records model and inference supply-chain provenance. PR records attacker privileges; AT records deployment prerequisites. |
| CA | CVSS VA/SA | CA records whether enforced resource ceilings contain token, API, compute, or workflow expenditure. VA/SA record realized availability impact. |
| TD | No direct CVSS equivalent | TD records whether the exploit sequence can be reconstructed from retained, correlated evidence. |

## Double-counting controls

1. CVSS records realized technical impact. AIVSS metrics record path properties;
   do not increase CVSS impact values merely because an AIVSS value is severe.
2. EX, PT, CA, and TD do not participate in Agentic Effect Class. This keeps
   their experimental additive contribution from also triggering MacroVector
   promotion.
3. The decision track never derives CISA Automatable from SR or Technical
   Impact from CVSS impact metrics.
4. Each report covers one coherent exploit path. Combining metric maxima from
   unrelated paths can create a profile that no attacker can realize.
5. Actual resource exhaustion may justify CVSS VA/SA impact while weak resource
   ceilings justify CA. Record evidence for both; they answer different
   questions, but the uncalibrated numeric adjustment must still be interpreted
   as experimental.

## Scope limits

The eight metrics are not a claim to cover all AI, safety, privacy, legal, or
business risk. They describe the Agentic AI exploit-path properties selected
for this candidate. Examples outside the profile include model bias, general
accuracy, regulatory jurisdiction, business criticality, safety cases,
training-data governance unrelated to the path, and portfolio-level risk
appetite.

OWASP ASI categories classify finding type. They are not score multipliers.
Organization context belongs outside portable technical severity.
