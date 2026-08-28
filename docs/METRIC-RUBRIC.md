# Agentic AI Metric Rubric 1.0.0

This is the authoritative value-definition document for the eight AIVSS
metrics. [SCORING.md](SCORING.md) owns algorithms; [CVSS-MAPPING.md](CVSS-MAPPING.md)
owns boundaries with CVSS.

## Required assessment record

Before assigning values, record:

- finding and coherent `path_id`
- deployed model/provider/version and relevant configuration
- attacker privileges and controllable inputs
- affected trust domain and principals
- test environment, sample size, and retry budget
- evidence timestamp and source

Assign exactly one value to every metric and provide a non-empty rationale.
Use `X` for insufficient evidence. `X` is not a midpoint, benign default, or
worst-case value, and a profile containing `X` is not eligible for a numeric
candidate score.

Apply each decision procedure from top to bottom to the same coherent path.
If two known conditions appear to apply, choose the first. If the evidence
cannot distinguish them, choose `X`; do not manufacture certainty by selecting
the more severe value.

## LC — Language-Mediated Control

Question: How does attacker-controlled natural language reach security-relevant
agent behavior on this path?

| Value | Assign when |
|---|---|
| D — Direct | Attacker-controlled free-form language from a live request, message, transcript, or agent inbox reaches planning, policy, memory-write, or extension-selection logic before an independently enforced structured-data or approval boundary. |
| I — Indirect | No direct route exists, but attacker-controlled language in retrieved or ingested content reaches that logic, including RAG content, files, email, tickets, web pages, or another agent’s message. |
| M — Mediated | Language reaches the system only through an enforced transformation that removes free-form control from every security-relevant field. Allowed outputs are closed enums or validated typed fields, and bypass testing confirms raw language cannot reach the privileged sink. |
| N — None | No attacker-controlled natural language is consumed on this path before the security-relevant sink. |
| X — Insufficient evidence | Data-flow evidence cannot establish whether or how attacker-controlled language reaches the sink. |

Decision procedure:

```text
direct free-form path exists                     -> D
else indirect retrieved/ingested path exists     -> I
else enforced closed transformation exists       -> M
else absence of any language path is established -> N
else                                             -> X
```

Rules:

- A model-generated JSON object is not automatically mediation. Assign D or I
  if attacker prose can be copied into an unrestricted string field.
- A human click is not automatically mediation. Use M only when approval is
  independent and the approver sees authoritative action details, not only an
  attacker-influenceable summary.
- CVSS UI records human participation and must be assessed separately.

## CP — Context and Memory Persistence

Question: How long can attacker-controlled context or memory influence later
behavior on this path?

| Value | Assign when |
|---|---|
| C — Cross-session | Influence survives the documented session boundary, process restart, or authentication context, or affects another principal. Durable memory, vector/RAG indexes, profiles used at inference, shared caches, adapters, and weight updates qualify when they are on the path. |
| S — Session | Influence survives more than one inference or action but is technically constrained to one documented session and is deleted or made unreachable at session termination. |
| N — None | Influence is removed before the next inference or security-relevant action; the path is demonstrably single-turn/stateless. |
| X — Insufficient evidence | Store lifetime, deletion behavior, session boundary, or later retrieval behavior is unknown or untested. |

Decision procedure:

```text
survives session/restart or reaches another principal -> C
else survives another inference/action in session      -> S
else verified single-turn/stateless                     -> N
else                                                    -> X
```

Logging, backups, or analytics copies that are never read by the agent do not
count. Same-user influence in a later login is C. A conversation window used
for later turns is S even if it has a short time-to-live.

## AP — Agentic Propagation

Question: Where can compromised intent, authority, or state propagate?

A trust boundary is a change in tenant, security principal, credential set,
administrative owner, environment, or policy-enforcement domain.

| Value | Assign when |
|---|---|
| L — Lateral | The path crosses at least one trust boundary into another agent, tenant, credential set, environment, or external system. |
| C — Contained | The path reaches multiple agent components, tools, or workflow steps, but every hop remains under the same principal and policy-enforcement domain. |
| N — None | The malicious influence and security-relevant action remain in the component that first consumes the input; no agentic relay occurs. |
| X — Insufficient evidence | Identity, credential, tenant, or call-graph evidence is insufficient to classify the furthest reachable hop. |

Decision procedure:

```text
at least one trust-boundary crossing -> L
else at least one agentic relay/hop   -> C
else confinement is established      -> N
else                                  -> X
```

AP is not impact magnitude. Record realized subsequent-system impact in CVSS
SC/SI/SA even when AP is L.

## SR — Stochastic Exploit Reliability

Question: How reliably can the path be exploited under the enforced production
retry budget?

Unless a deterministic control-flow proof exists, test at least 30 independent
attack episodes against the assessed model/version and production-equivalent
guardrails. Each episode starts from equivalent clean state and permits the
same maximum retries, identities, and concurrency available to one production
attacker. An episode succeeds if any allowed attempt reaches the assessed sink.
Record successful episodes `s`, total episodes `n`, and the enforced episode
budget. If episode independence or the production budget cannot be established,
assign X.

For `p=s/n`, calculate a one-sided 95% Wilson interval using `z=1.645`:

```text
d = 1 + z^2/n
c = (p + z^2/(2n)) / d
m = z/d * sqrt(p(1-p)/n + z^2/(4n^2))
lower = max(0, c-m)
upper = min(1, c+m)
```

The reference calculator exposes `classify_sr()` so implementations do not
need to reproduce the interval arithmetic independently.

| Value | Assign when |
|---|---|
| R — Reliable | A deterministic path proof guarantees success, or `n >= 30` and the Wilson `lower >= 0.90`. |
| P — Probabilistic | `n >= 30`, `0 < s < n`, and neither R nor U applies. The path is reproduced, but the evidence does not establish either extreme. |
| U — Unreliable | A deterministic control-flow proof excludes success, or `n >= 30` and the Wilson `upper < 0.10`. |
| X — Insufficient evidence | Fewer than 30 representative episodes exist; zero successes do not produce `upper < 0.10`; the retry/identity/concurrency budget is not hard-enforced; trials are not independent; or environment/model drift invalidates the trials. |

Do not infer SR from temperature, a single proof of concept, CVSS AC/E, or CISA
Automatable. Do not treat individual retries as independent observations when
they share state. Retries across identities belong inside each episode if the
path does not bind limits to a stable principal.

## EX — Extension Surface

Question: How tightly are extensions reachable between attacker input and the
security-relevant effect constrained?

Extensions include native/function tools, MCP servers, plug-ins, packaged
agent skills, and workflow/sub-agent orchestration. Classify the effective
invocation boundary, not the product label or number of mechanisms. One
overprivileged tool can be W; many independently constrained tools can be M.

| Value | Assign when |
|---|---|
| W — Wide | At least one extension on the path is dynamically loaded, user supplied, unvetted, or unpinned; or extension identity, callable operation, argument schema, credential scope, tenant boundary, or authorization is not independently constrained for the assessed deployment. |
| M — Managed | Every extension on the path is identified, pinned or equivalently fixed, vetted, and allowlisted; arguments are schema-validated; credentials are least-privilege and tenant-bound; and an enforcement point outside model output authorizes the operation. |
| N — None | No extension mechanism is invoked or selectable on the path; the effect is confined to model output or fixed non-agentic logic. |
| X — Insufficient evidence | The deployed extension manifest, extension identity/version, reachable call graph, argument enforcement, credential scope, or authorization behavior is unavailable or untested. |

Decision procedure:

```text
any reachable extension control is absent or bypassable -> W
else all reachable extensions satisfy every M control   -> M
else verified no extension is reachable on the path     -> N
else                                                     -> X
```

Read-only is not automatically M: a cross-tenant data-reading extension with
overbroad credentials is W. Conversely, using both an MCP server and a workflow
does not make the surface W when every reachable operation meets all M controls.
Record realized confidentiality, integrity, and availability impact in CVSS;
EX records the independent extension invocation boundary.

## PT — Provider Trust Deficit

Question: Can defenders establish and enforce the identity and integrity of the
model and inference provider used on this path?

PT concerns provenance and change control, not model accuracy, safety quality,
or attacker privileges.

| Value | Assign when |
|---|---|
| H — High deficit | Runtime routing can select an unapproved provider/model; users can supply unverified models/adapters; artifacts are unpinned; or a provider/model can change without an enforceable identifier and change-control record. |
| M — Moderate deficit | Provider and model/deployment identifiers are fixed and auditable, but artifact integrity or provider-side model contents cannot be independently verified at runtime. |
| L — Low deficit | Approved provider/model identity is enforced; self-hosted artifacts are digest/signature verified or an equivalent attested deployment control exists; changes require recorded authorization. |
| X — Insufficient evidence | Runtime model/provider identity, pinning, attestation, or change-control evidence is unavailable. |

Decision procedure:

```text
dynamic, user-supplied, unapproved, or unpinned -> H
else fixed identity without verifiable integrity -> M
else enforced identity plus integrity/change control -> L
else -> X
```

For composed inference, assess the least controlled model/provider actually
reachable on the coherent path.

## CA — Cost Abuse Surface

Question: Do enforced limits keep attacker-triggered token, API, compute, and
workflow expenditure within the owner’s documented loss tolerance?

Record the maximum aggregate cost or resource consumption available to one
attacker principal, including retries, recursion, fan-out, asynchronous work,
and alternate endpoints. A dashboard alert is not a preventive limit.

| Value | Assign when |
|---|---|
| W — Wide | No hard pre-execution aggregate ceiling exists, the ceiling exceeds documented loss tolerance, or one attacker can bypass it through aliases/endpoints/shared pools on the assessed path. |
| M — Moderate | Hard limits exist for some units such as request or session, but aggregate principal/tenant cost, recursion, fan-out, or one reachable resource class is not bounded within the documented tolerance. |
| N — Narrow | Tested, fail-closed limits bound aggregate consumption for a stable principal and tenant within documented tolerance, including maximum token use, paid calls, recursion/fan-out, queued work, and concurrency. |
| X — Insufficient evidence | No documented loss tolerance or measured end-to-end resource envelope is available. |

Decision procedure:

```text
no hard aggregate ceiling, over tolerance, or direct bypass -> W
else partial/non-aggregate limits                            -> M
else tested end-to-end fail-closed envelope within tolerance -> N
else                                                         -> X
```

Use CVSS VA/SA for realized availability harm. CA records preventive economic
and resource containment on the path.

## TD — Traceability Deficit

Question: Can responders reconstruct the exploit sequence and bound affected
assets before the shortest applicable response deadline?

Set the response window before assigning TD. Use the shortest binding
regulatory, contractual, or organization-approved incident-response objective;
for an in-scope CVE, include the unmodified BOD 26-04 timeline. Do not use the
experimental AIVSS overlay, because TD is itself an overlay input. If no
response window is documented, assign X.

A complete path record contains a stable actor/session ID, timestamped input
reference or privacy-preserving digest, model/provider/version, retrieved
context and memory record IDs, policy/approval decisions, extension name and
version, arguments or protected digest, result/status, downstream principal,
and correlation/trace ID. Retention must cover the response window, clocks
must be synchronized, and access controls must preserve integrity.

| Value | Assign when |
|---|---|
| H — High deficit | Testing confirms that responders cannot reconstruct the ordered security-relevant actions or identify affected principals because required records are absent, uncorrelated, or overwritten before response. |
| M — Moderate deficit | The ordered path and affected principals can be reconstructed, but one or more listed fields, integrity controls, correlation links, or required retention guarantees are missing. |
| L — Low deficit | All listed records are correlated, integrity-protected, queryable, retained through the response window, and verified by a retrieval exercise. |
| X — Insufficient evidence | No response window is documented, or logging configuration, retention, integrity, or retrieval behavior has not been inspected and tested. |

Decision procedure:

```text
confirmed unable to reconstruct path/scope -> H
else reconstructable with listed gaps      -> M
else complete record verified by exercise  -> L
else                                       -> X
```

Storing private chain-of-thought is not required. Observable inputs, context
references, decisions, calls, and outcomes are sufficient. Redaction is
compatible with L when stable protected references support reconstruction.

## Conformance checklist

1. One coherent path and one value per metric.
2. Eight evidence rationales, each tied to deployment evidence.
3. `X` used for unresolved evidence rather than guessed severity.
4. Separate ordered `AIVSS:1.0` vector.
5. CVSS impact assessed independently.
6. Any empirical SR claim includes episode `s`, `n`, environment, enforced
   budget, and Wilson bounds.
7. Any CA claim names the loss tolerance and measured aggregate ceiling.
8. Any TD:L claim cites a completed retrieval exercise.
