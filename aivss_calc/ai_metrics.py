"""The eight-metric AIVSS Agentic AI profile.

LC, CP, AP, and SR classify agentic effect. EX, PT, CA, and TD feed an
explicitly experimental adjustment. Every conformant profile records all eight.

The class is an ordinal label, not a cardinal score.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from typing import Any

from .versions import EXTENSION_VECTOR_VERSION

AIVSS_EXTENSION_VERSION = EXTENSION_VECTOR_VERSION
AIVSS_EXTENSION_PREFIX = f"AIVSS:{AIVSS_EXTENSION_VERSION}"
ADJUSTMENT_STATUS = "experimental-uncalibrated"
EFFECT_CLASS_STATUS = "candidate-unvalidated"
UNKNOWN_VALUE = "X"

LC_VALUES: dict[str, tuple[str, str]] = {
    "D": (
        "Direct",
        "Attacker-supplied natural language reaches a privileged decision or "
        "tool-invocation path without mediation.",
    ),
    "I": (
        "Indirect",
        "Attacker-controlled language enters through retrieved or ingested content "
        "(documents, web pages, email, files) and influences security-relevant behaviour.",
    ),
    "M": (
        "Mediated",
        "An independently enforced transformation reduces language to closed, "
        "validated fields before every security-relevant sink.",
    ),
    "N": ("None", "No natural-language path to security-relevant behaviour."),
    "X": (
        "Insufficient evidence",
        "Available evidence cannot determine the language-control path.",
    ),
}

CP_VALUES: dict[str, tuple[str, str]] = {
    "C": (
        "Cross-session memory",
        "Attacker-controlled context or memory persists in durable stores — vector "
        "databases, long-term agent memory, episodic memory banks, RAG indexes, "
        "user profiles, or training/fine-tuning data — and remains reachable after "
        "the originating session ends.",
    ),
    "S": (
        "Session context",
        "Attacker-controlled context persists only in ephemeral session state "
        "(conversation buffer, in-memory working context, session-scoped cache), and "
        "testing confirms it is unreachable after the session boundary.",
    ),
    "N": (
        "None",
        "Single-turn or stateless; no attacker-controlled context or memory carryover "
        "between requests.",
    ),
    "X": (
        "Insufficient evidence",
        "Available evidence cannot determine context or memory persistence.",
    ),
}

AP_VALUES: dict[str, tuple[str, str]] = {
    "L": (
        "Lateral",
        "Compromised intent, instructions, memory, or authority crosses a trust boundary "
        "to other agents, other tenants, or downstream systems.",
    ),
    "C": (
        "Contained",
        "Propagation occurs within the agent's own tool and action scope but does not "
        "cross a trust boundary.",
    ),
    "N": ("None", "Effect is confined to the initially affected component."),
    "X": (
        "Insufficient evidence",
        "Available evidence cannot determine propagation scope.",
    ),
}

SR_VALUES: dict[str, tuple[str, str]] = {
    "R": (
        "Reliable",
        "A deterministic proof guarantees success, or the one-sided 95% Wilson lower "
        "bound implies at least 90% cumulative success within the enforced production "
        "retry budget.",
    ),
    "P": (
        "Probabilistic",
        "At least 30 representative attempts exist and the confidence bounds support "
        "neither the Reliable nor Unreliable threshold.",
    ),
    "U": (
        "Unreliable",
        "A deterministic proof excludes success, or the one-sided 95% Wilson upper "
        "bound implies less than 10% cumulative success within the enforced production "
        "retry budget.",
    ),
    "X": (
        "Insufficient evidence",
        "No representative retry-budget evidence is available.",
    ),
}

EX_VALUES: dict[str, tuple[str, str]] = {
    "W": (
        "Wide",
        "A reachable extension is dynamic or unvetted, or its identity, callable "
        "operations, arguments, credentials, or authority are not independently "
        "constrained for the assessed deployment.",
    ),
    "M": (
        "Managed",
        "One or more vetted extensions are fixed and allowlisted, with schema-validated "
        "arguments and least-privilege credentials enforced outside model output.",
    ),
    "N": (
        "None",
        "No security-relevant extensions on the exploitation path — read-only responses, "
        "fixed deterministic actions, or no tool/skill/MCP/plugin/workflow invocation.",
    ),
    "X": (
        "Insufficient evidence",
        "Available evidence cannot determine the extension surface.",
    ),
}

PT_VALUES: dict[str, tuple[str, str]] = {
    "H": (
        "High deficit",
        "Runtime controls do not enforce the approved provider, model, and deployment "
        "configuration, or routing can change them outside authorized change control.",
    ),
    "M": (
        "Moderate deficit",
        "Provider, model, and deployment configuration are enforced and changes are "
        "auditable, but the served artifact or provider-side content cannot be "
        "independently verified at runtime.",
    ),
    "L": (
        "Low deficit",
        "Provider, model, and deployment configuration are enforced; artifact identity "
        "or equivalent attestation is verified; changes require recorded authorization.",
    ),
    "X": ("Insufficient evidence", "Model/provider provenance cannot be established."),
}

CA_VALUES: dict[str, tuple[str, str]] = {
    "W": (
        "Wide",
        "No finite hard aggregate ceiling exists for attacker-triggered consumption, "
        "or testing demonstrates a bypass.",
    ),
    "M": (
        "Moderate",
        "A finite hard ceiling exists and no bypass is demonstrated, but coverage is "
        "incomplete or enforcement is not fail-closed.",
    ),
    "N": (
        "Narrow",
        "Tested fail-closed aggregate limits cover tokens, paid calls, compute, retries, "
        "fan-out, queued work, and concurrency for a stable principal and tenant.",
    ),
    "X": (
        "Insufficient evidence",
        "Aggregate economic limits on the path are unknown.",
    ),
}

TD_VALUES: dict[str, tuple[str, str]] = {
    "H": (
        "High deficit",
        "Testing confirms responders cannot reconstruct ordered security-relevant "
        "actions or bound affected principals from retained records.",
    ),
    "M": (
        "Moderate deficit",
        "The ordered path and affected principals are reconstructable, but required "
        "fields, correlation, integrity, or tested retention controls are incomplete.",
    ),
    "L": (
        "Low deficit",
        "A retrieval exercise verifies correlated, integrity-protected records of inputs, "
        "context references, model identity, policy decisions, calls, and outcomes.",
    ),
    "X": (
        "Insufficient evidence",
        "Audit-log coverage and retention cannot be established.",
    ),
}

EX_RISK_DELTA: dict[str, Decimal | None] = {
    "W": Decimal("0.4"),
    "M": Decimal("0.15"),
    "N": Decimal("0.0"),
    "X": None,
}
PT_RISK_DELTA: dict[str, Decimal | None] = {
    "H": Decimal("0.3"),
    "M": Decimal("0.1"),
    "L": Decimal("0.0"),
    "X": None,
}
CA_RISK_DELTA: dict[str, Decimal | None] = {
    "W": Decimal("0.3"),
    "M": Decimal("0.1"),
    "N": Decimal("0.0"),
    "X": None,
}
TD_RISK_DELTA: dict[str, Decimal | None] = {
    "H": Decimal("0.5"),
    "M": Decimal("0.2"),
    "L": Decimal("0.0"),
    "X": None,
}

ADJUSTMENT_RISK_DELTAS: dict[str, dict[str, Decimal | None]] = {
    "EX": EX_RISK_DELTA,
    "PT": PT_RISK_DELTA,
    "CA": CA_RISK_DELTA,
    "TD": TD_RISK_DELTA,
}


def _risk_delta(metric: str, value: str) -> Decimal:
    table = ADJUSTMENT_RISK_DELTAS[metric]
    if value not in table:
        raise ValueError(
            f"Illegal value {value!r} for Agentic AI metric {metric!r}; "
            f"expected one of {sorted(table)}"
        )
    delta = table[value]
    if delta is None:
        raise ValueError(f"Cannot calculate a score while {metric}:X is unresolved")
    return delta


def ex_risk_delta(ex: str) -> float:
    return float(_risk_delta("EX", ex))


def pt_risk_delta(pt: str) -> float:
    return float(_risk_delta("PT", pt))


def ca_risk_delta(ca: str) -> float:
    return float(_risk_delta("CA", ca))


def td_risk_delta(td: str) -> float:
    return float(_risk_delta("TD", td))


def agentic_risk_delta(*, ex: str, pt: str, ca: str, td: str) -> float:
    """Exact candidate adjustment. The weights are explicitly uncalibrated."""
    return float(
        _risk_delta("EX", ex)
        + _risk_delta("PT", pt)
        + _risk_delta("CA", ca)
        + _risk_delta("TD", td)
    )


@dataclass(frozen=True)
class CandidateAdjustment:
    """Transparent result for the uncalibrated additive candidate model."""

    value: float
    raw_value: float
    delta: float
    capped: bool


@dataclass(frozen=True)
class SRClassification:
    """Reproducible result of the empirical SR decision rule."""

    value: str
    lower_bound: float | None
    upper_bound: float | None
    method: str


def classify_sr(
    *,
    successes: int | None = None,
    episodes: int | None = None,
    production_equivalent: bool = False,
    budget_enforced: bool = False,
    independent: bool = False,
    deterministic_outcome: str | None = None,
) -> SRClassification:
    """Classify SR using the rubric's proof or one-sided Wilson rule."""
    if deterministic_outcome is not None:
        if deterministic_outcome == "success":
            return SRClassification("R", 1.0, 1.0, "deterministic-proof")
        if deterministic_outcome == "failure":
            return SRClassification("U", 0.0, 0.0, "deterministic-proof")
        raise ValueError("deterministic_outcome must be success, failure, or omitted")

    for name, value in (
        ("production_equivalent", production_equivalent),
        ("budget_enforced", budget_enforced),
        ("independent", independent),
    ):
        if type(value) is not bool:
            raise ValueError(f"{name} must be true or false")
    if successes is None or episodes is None:
        return SRClassification("X", None, None, "insufficient-evidence")
    if type(successes) is not int or type(episodes) is not int:
        raise ValueError("successes and episodes must be integers")
    if episodes <= 0 or not 0 <= successes <= episodes:
        raise ValueError(
            "episodes must be positive and successes must be in [0, episodes]"
        )
    if (
        episodes < 30
        or not production_equivalent
        or not budget_enforced
        or not independent
    ):
        return SRClassification("X", None, None, "insufficient-evidence")

    n = Decimal(episodes)
    p = Decimal(successes) / n
    z = Decimal("1.645")
    denominator = Decimal(1) + (z**2 / n)
    center = (p + z**2 / (Decimal(2) * n)) / denominator
    margin = (
        z / denominator * (p * (Decimal(1) - p) / n + z**2 / (Decimal(4) * n**2)).sqrt()
    )
    lower = max(Decimal(0), center - margin)
    upper = min(Decimal(1), center + margin)
    if lower >= Decimal("0.90"):
        value = "R"
    elif upper < Decimal("0.10"):
        value = "U"
    else:
        value = "P"
    return SRClassification(value, float(lower), float(upper), "wilson-one-sided-95")


def classify_ca(
    *,
    ceiling_defined: bool | None,
    coverage_complete: bool | None,
    fail_closed: bool | None,
    bypass_demonstrated: bool | None,
) -> str:
    """Classify cost-abuse containment from policy-independent control facts."""
    values = {
        "ceiling_defined": ceiling_defined,
        "coverage_complete": coverage_complete,
        "fail_closed": fail_closed,
        "bypass_demonstrated": bypass_demonstrated,
    }
    for name, value in values.items():
        if value is not None and type(value) is not bool:
            raise ValueError(f"{name} must be true, false, or unknown")
    if bypass_demonstrated is True or ceiling_defined is False:
        return "W"
    if bypass_demonstrated is None or ceiling_defined is None:
        return "X"
    if coverage_complete is None or fail_closed is None:
        return "X"
    if coverage_complete and fail_closed:
        return "N"
    return "M"


def classify_td(
    *,
    retrieval_tested: bool | None,
    ordered_actions_reconstructable: bool | None,
    affected_principals_bounded: bool | None,
    required_fields_complete: bool | None,
    integrity_protected: bool | None,
    retention_verified: bool | None,
) -> str:
    """Classify traceability from a retrieval exercise and observable controls."""
    values = {
        "retrieval_tested": retrieval_tested,
        "ordered_actions_reconstructable": ordered_actions_reconstructable,
        "affected_principals_bounded": affected_principals_bounded,
        "required_fields_complete": required_fields_complete,
        "integrity_protected": integrity_protected,
        "retention_verified": retention_verified,
    }
    for name, value in values.items():
        if value is not None and type(value) is not bool:
            raise ValueError(f"{name} must be true, false, or unknown")
    if retrieval_tested is not True:
        return "X"
    if (
        ordered_actions_reconstructable is False
        or affected_principals_bounded is False
    ):
        return "H"
    if (
        ordered_actions_reconstructable is None
        or affected_principals_bounded is None
        or required_fields_complete is None
        or integrity_protected is None
        or retention_verified is None
    ):
        return "X"
    if required_fields_complete and integrity_protected and retention_verified:
        return "L"
    return "M"


def _validated_base_score(score: int | float | Decimal) -> Decimal:
    if isinstance(score, bool) or not isinstance(score, (int, float, Decimal)):
        raise ValueError(
            f"score must be a finite decimal in [0.0, 10.0]; got {score!r}"
        )
    try:
        base = Decimal(str(score))
    except Exception as exc:
        raise ValueError(
            f"score must be a finite decimal in [0.0, 10.0]; got {score!r}"
        ) from exc
    if not base.is_finite() or not Decimal("0.0") <= base <= Decimal("10.0"):
        raise ValueError(f"score must be in [0.0, 10.0]; got {score!r}")
    if base != base.quantize(Decimal("0.1")):
        raise ValueError(f"score must have at most one decimal place; got {score!r}")
    return base


def candidate_adjustment(
    score: int | float | Decimal, *, ex: str, pt: str, ca: str, td: str
) -> CandidateAdjustment:
    base = _validated_base_score(score)
    delta = (
        _risk_delta("EX", ex)
        + _risk_delta("PT", pt)
        + _risk_delta("CA", ca)
        + _risk_delta("TD", td)
    )
    raw = Decimal("0.0") if base == 0 else base + delta
    capped = raw > Decimal("10.0")
    value = min(Decimal("10.0"), raw).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    return CandidateAdjustment(
        value=float(value),
        raw_value=float(raw),
        delta=float(delta),
        capped=capped,
    )


def apply_agentic_risk(
    score: int | float | Decimal, *, ex: str, pt: str, ca: str, td: str
) -> float:
    """Apply the experimental adjustment with exact decimal half-up rounding.

    A zero-impact CVSS result remains zero: assurance deficits do not create a
    vulnerability impact where CVSS records none.
    """
    return candidate_adjustment(score, ex=ex, pt=pt, ca=ca, td=td).value


def apply_td_risk(score: int | float | Decimal, td: str) -> float:
    """Backward-compatible TD-only adjustment."""
    base = _validated_base_score(score)
    if base == 0:
        return 0.0
    value = min(Decimal("10.0"), base + _risk_delta("TD", td))
    return float(value.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


ADJUSTMENT_AGENTIC_METRICS: dict[str, dict[str, tuple[str, str]]] = {
    "EX": EX_VALUES,
    "PT": PT_VALUES,
    "CA": CA_VALUES,
    "TD": TD_VALUES,
}

CLASSIFYING_AGENTIC_METRICS: dict[str, dict[str, tuple[str, str]]] = {
    "LC": LC_VALUES,
    "CP": CP_VALUES,
    "AP": AP_VALUES,
    "SR": SR_VALUES,
}

AGENTIC_METRICS: dict[str, dict[str, tuple[str, str]]] = {
    **CLASSIFYING_AGENTIC_METRICS,
    **ADJUSTMENT_AGENTIC_METRICS,
}

AI_METRICS = AGENTIC_METRICS

AGENTIC_METRIC_ORDER: tuple[str, ...] = ("LC", "CP", "AP", "SR", "EX", "PT", "CA", "TD")
AI_METRIC_ORDER = AGENTIC_METRIC_ORDER

AGENTIC_EFFECT_CLASS_LABELS: dict[str, str] = {
    "A0": "No class-based promotion",
    "A1": "Agentic characteristics present",
    "A2": "Substantial classifying interaction",
    "AX": "Insufficient evidence to classify",
}


@dataclass(frozen=True)
class AIProfile:
    """One coherent exploit-path profile containing all eight metrics."""

    lc: str
    cp: str
    ap: str
    sr: str
    ex: str
    pt: str
    ca: str
    td: str

    def __post_init__(self) -> None:
        for name, value in (
            ("LC", self.lc),
            ("CP", self.cp),
            ("AP", self.ap),
            ("SR", self.sr),
        ):
            if value not in CLASSIFYING_AGENTIC_METRICS[name]:
                raise ValueError(
                    f"Illegal value {value!r} for Agentic AI metric {name!r}; "
                    f"expected one of {sorted(CLASSIFYING_AGENTIC_METRICS[name])}"
                )
        for name, value in (
            ("EX", self.ex),
            ("PT", self.pt),
            ("CA", self.ca),
            ("TD", self.td),
        ):
            if value not in ADJUSTMENT_AGENTIC_METRICS[name]:
                raise ValueError(
                    f"Illegal value {value!r} for Agentic AI metric {name!r}; "
                    f"expected one of {sorted(ADJUSTMENT_AGENTIC_METRICS[name])}"
                )

    @property
    def is_absent(self) -> bool:
        return self.lc == "N" and self.cp == "N" and self.ap == "N" and self.sr == "U"

    @property
    def complete(self) -> bool:
        return all(
            getattr(self, name.lower()) != UNKNOWN_VALUE
            for name in AGENTIC_METRIC_ORDER
        )

    def agentic_effect_class(self) -> str:
        return self.effect_class()

    def effect_class(self) -> str:
        if any(
            getattr(self, name.lower()) == UNKNOWN_VALUE
            for name in CLASSIFYING_AGENTIC_METRICS
        ):
            return "AX"
        if self.ap == "L":
            return "A2"
        if self.lc in ("D", "I") and self.cp == "C":
            return "A2"
        if self.lc == "D" and self.sr == "R":
            return "A2"
        if self.is_absent:
            return "A0"
        return "A1"

    def to_vector_fragment(self) -> str:
        return "/".join(
            f"{name}:{getattr(self, name.lower())}" for name in AGENTIC_METRIC_ORDER
        )

    def to_vector(self) -> str:
        return f"{AIVSS_EXTENSION_PREFIX}/{self.to_vector_fragment()}"

    def describe(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for name, values in AGENTIC_METRICS.items():
            value = getattr(self, name.lower())
            out[name] = f"{value} ({values[value][0]})"
        return out


def validate_metric_evidence(
    profile: AIProfile, evidence: dict[str, dict[str, Any]]
) -> None:
    """Validate evidence shape and executable SR/CA/TD classification facts."""
    expected_metrics = set(AGENTIC_METRIC_ORDER)
    if not isinstance(evidence, dict) or set(evidence) != expected_metrics:
        raise ValueError(
            "metric_evidence must contain exactly LC, CP, AP, SR, EX, PT, CA, and TD"
        )
    common = {"rationale", "evidence_refs"}
    sr_fields = {
        "method",
        "deterministic_outcome",
        "successes",
        "episodes",
        "retry_budget",
        "production_equivalent",
        "budget_enforced",
        "independent",
        "lower_bound",
        "upper_bound",
    }
    ca_fields = {
        "ceiling_defined",
        "coverage_complete",
        "fail_closed",
        "bypass_demonstrated",
    }
    td_fields = {
        "retrieval_tested",
        "ordered_actions_reconstructable",
        "affected_principals_bounded",
        "required_fields_complete",
        "integrity_protected",
        "retention_verified",
    }
    for name in AGENTIC_METRIC_ORDER:
        entry = evidence[name]
        if not isinstance(entry, dict):
            raise ValueError(f"metric_evidence[{name!r}] must be an object")
        rationale = entry.get("rationale")
        refs = entry.get("evidence_refs")
        if not isinstance(rationale, str) or not rationale.strip():
            raise ValueError(f"{name} evidence rationale must be non-empty")
        if (
            not isinstance(refs, list)
            or not refs
            or any(not isinstance(ref, str) or not ref.strip() for ref in refs)
        ):
            raise ValueError(f"{name} evidence_refs must contain non-empty references")

        allowed = common
        if name == "SR":
            allowed = common | sr_fields
        elif name == "CA":
            allowed = common | ca_fields
        elif name == "TD":
            allowed = common | td_fields
        extras = set(entry) - allowed
        if extras:
            raise ValueError(f"{name} evidence has unknown fields: {sorted(extras)}")

    sr = evidence["SR"]
    method = sr.get("method")
    if method == "deterministic-proof":
        result = classify_sr(deterministic_outcome=sr.get("deterministic_outcome"))
        required = common | {"method", "deterministic_outcome"}
    elif method == "empirical":
        required = common | (
            sr_fields - {"deterministic_outcome"}
        )
        missing = required - set(sr)
        if missing:
            raise ValueError(f"SR empirical evidence is missing {sorted(missing)}")
        retry_budget = sr["retry_budget"]
        if type(retry_budget) is not int or retry_budget < 1:
            raise ValueError("SR retry_budget must be a positive integer")
        result = classify_sr(
            successes=sr["successes"],
            episodes=sr["episodes"],
            production_equivalent=sr["production_equivalent"],
            budget_enforced=sr["budget_enforced"],
            independent=sr["independent"],
        )
        for key, calculated in (
            ("lower_bound", result.lower_bound),
            ("upper_bound", result.upper_bound),
        ):
            supplied = sr[key]
            if (
                isinstance(supplied, bool)
                or not isinstance(supplied, (int, float))
                or calculated is None
                or abs(float(supplied) - calculated) > 0.0005
            ):
                raise ValueError(f"SR {key} does not match the Wilson calculation")
    elif method == "insufficient-evidence":
        result = SRClassification("X", None, None, "insufficient-evidence")
        required = common | {"method"}
    else:
        raise ValueError(
            "SR evidence method must be deterministic-proof, empirical, "
            "or insufficient-evidence"
        )
    if set(sr) != required:
        raise ValueError("SR evidence fields do not match its selected method")
    if result.value != profile.sr:
        raise ValueError("SR evidence does not support the vector value")

    ca = evidence["CA"]
    if set(ca) != common | ca_fields:
        raise ValueError("CA evidence must provide all four containment observations")
    if classify_ca(**{key: ca[key] for key in ca_fields}) != profile.ca:
        raise ValueError("CA evidence does not support the vector value")

    td = evidence["TD"]
    if set(td) != common | td_fields:
        raise ValueError("TD evidence must provide all six traceability observations")
    if classify_td(**{key: td[key] for key in td_fields}) != profile.td:
        raise ValueError("TD evidence does not support the vector value")


def parse_aivss_vector(vector: str) -> AIProfile:
    """Parse a separate FIRST-style AIVSS extension vector."""
    parts = vector.strip().split("/")
    if not parts or parts[0] != AIVSS_EXTENSION_PREFIX:
        raise ValueError(
            f"AIVSS extension vector must begin with {AIVSS_EXTENSION_PREFIX!r}"
        )
    found: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError(f"Malformed AIVSS metric segment {part!r}")
        key, _, value = part.partition(":")
        if key == "TA":
            key = "TD"
        if key not in AGENTIC_METRICS:
            raise ValueError(f"Unknown AIVSS metric {key!r}")
        if key in found:
            raise ValueError(f"Duplicate AIVSS metric {key!r}")
        expected_index = len(found)
        if (
            expected_index >= len(AGENTIC_METRIC_ORDER)
            or key != AGENTIC_METRIC_ORDER[expected_index]
        ):
            expected = (
                AGENTIC_METRIC_ORDER[expected_index]
                if expected_index < len(AGENTIC_METRIC_ORDER)
                else "end of vector"
            )
            raise ValueError(
                f"AIVSS metric {key!r} is out of order; expected {expected!r}"
            )
        if value not in AGENTIC_METRICS[key]:
            raise ValueError(
                f"Illegal value {value!r} for AIVSS metric {key!r}; "
                f"expected one of {sorted(AGENTIC_METRICS[key])}"
            )
        found[key] = value

    missing = [name for name in AGENTIC_METRIC_ORDER if name not in found]
    if missing:
        raise ValueError(
            "A conformant AIVSS extension vector must specify all eight metrics; "
            f"missing: {', '.join(missing)}"
        )
    return AIProfile(**{name.lower(): found[name] for name in AGENTIC_METRIC_ORDER})


def split_ai_vector(vector: str) -> tuple[str, AIProfile | None]:
    """Parse display form containing separate CVSS and AIVSS vectors.

    Appending AIVSS metrics inside a CVSS vector is rejected because FIRST's
    Extensions Framework requires extension vectors to be listed separately.
    """
    text = vector.strip()
    if " " in text:
        cvss_vector, aivss_vector = text.split(None, 1)
        return cvss_vector, parse_aivss_vector(aivss_vector)
    for part in text.split("/"):
        key, _, _ = part.partition(":")
        if key in AGENTIC_METRICS:
            raise ValueError(
                f"AIVSS metrics must be in a separate {AIVSS_EXTENSION_PREFIX} "
                "extension vector"
            )
    return text, None
