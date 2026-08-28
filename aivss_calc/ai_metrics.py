"""The AIVSS Agentic AI metric group: LC, CP, AP, SR (scored) and EX, TD (mandatory risk factors).

EX (Extension Surface) captures tool, MCP, plugin, skill, and workflow invocation on the
attack path — mechanisms CVSS does not name. TD (Traceability Deficit) captures whether
post-incident reconstruction of agent reasoning and tool calls is feasible. Both are
required in every conformant assessment and adjust the published AIVSS score.

Completes Appendix E sections 3, 4 and 8, which name the metrics and use the
values LC:D / CP:C / AP:L / SR:R / TD:H in a worked example but never define the
value sets, the AI Effect Class derivation rule, or the parsing rules.

The AI Effect Class is derived by a boolean ladder rather than by arithmetic.
This is deliberate: Appendix E's objection to the withdrawn uplift model is that
it "treats ordinal factors as additive", so no ordinal AI metric value is ever
summed, averaged, or multiplied anywhere in this module.
"""

from __future__ import annotations

from dataclasses import dataclass

from .cvss_score import round_half_up

# Each metric maps value code -> (short label, definition). Ordered most severe
# first; the last entry of each scored metric is the benign case.
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
        "Language influences behaviour only through a constrained interface: "
        "schema-bound arguments, allowlisted actions, or enforced human approval.",
    ),
    "N": ("None", "No natural-language path to security-relevant behaviour."),
}

CP_VALUES: dict[str, tuple[str, str]] = {
    "C": (
        "Cross-session",
        "Attacker-controlled context persists in long-term memory, a vector store, or "
        "training data, and influences later sessions or other users.",
    ),
    "S": ("Session", "Attacker-controlled context persists only within the active session."),
    "N": ("None", "Single-turn only; no carryover of attacker-controlled context."),
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
}

SR_VALUES: dict[str, tuple[str, str]] = {
    "R": (
        "Reliable",
        "Succeeds on essentially every attempt, or the attacker can retry freely until "
        "it succeeds.",
    ),
    "P": (
        "Probabilistic",
        "Succeeds intermittently; retry is possible but rate-limited, detectable, or "
        "otherwise constrained.",
    ),
    "U": ("Unreliable", "Rarely reproducible, with no practical retry path."),
}

TD_VALUES: dict[str, tuple[str, str]] = {
    "H": (
        "High deficit",
        "No reasoning trace and no tool-call audit; post-incident reconstruction of why "
        "the system acted is infeasible.",
    ),
    "M": (
        "Moderate deficit",
        "Partial logging; reconstruction is possible with significant effort.",
    ),
    "L": (
        "Low deficit",
        "Prompt, reasoning-trace, and tool-call logging retained and queryable.",
    ),
}

# Traceability Deficit risk adjustment applied to every published AIVSS score.
# Ordinal rubric: higher deficit increases operational risk because incident scope
# cannot be bounded. Capped at 10.0 like all AIVSS outputs.
TD_RISK_DELTA: dict[str, float] = {
    "H": 0.5,
    "M": 0.2,
    "L": 0.0,
}


def td_risk_delta(td: str) -> float:
    """Return the severity adjustment for a TD value."""
    if td not in TD_RISK_DELTA:
        raise ValueError(
            f"Illegal value {td!r} for AI metric 'TD'; "
            f"expected one of {sorted(TD_RISK_DELTA)}"
        )
    return TD_RISK_DELTA[td]


def apply_td_risk(score: float, td: str) -> float:
    """Apply the TD ceiling-delta to a base severity score."""
    return round_half_up(min(10.0, score + td_risk_delta(td)), 1)


EX_VALUES: dict[str, tuple[str, str]] = {
    "W": (
        "Wide",
        "Multiple extension mechanisms are in play — native tools, MCP servers, plugins, "
        "agentic skills, and/or workflow steps — with a broad or dynamically loaded "
        "invocation surface reachable from the vulnerable path.",
    ),
    "M": (
        "Moderate",
        "One primary extension class (e.g. allowlisted tools only, or a fixed MCP bundle) "
        "with constrained invocation; no arbitrary plugin or workflow composition.",
    ),
    "N": (
        "Narrow",
        "No security-relevant extensions on the exploitation path — read-only responses, "
        "fixed deterministic actions, or no tool/skill/MCP/plugin/workflow invocation.",
    ),
}

# Extension Surface risk adjustment. CVSS SC/SI/SA capture downstream *impact* of tool
# reach; EX captures *what extension mechanisms exist* on the attack path (ASI02, ASI04).
EX_RISK_DELTA: dict[str, float] = {
    "W": 0.4,
    "M": 0.15,
    "N": 0.0,
}


def ex_risk_delta(ex: str) -> float:
    """Return the severity adjustment for an EX value."""
    if ex not in EX_RISK_DELTA:
        raise ValueError(
            f"Illegal value {ex!r} for Agentic AI metric 'EX'; "
            f"expected one of {sorted(EX_RISK_DELTA)}"
        )
    return EX_RISK_DELTA[ex]


def agentic_risk_delta(*, ex: str, td: str) -> float:
    """Combined mandatory risk-factor adjustment (EX + TD)."""
    return ex_risk_delta(ex) + td_risk_delta(td)


def apply_agentic_risk(score: float, *, ex: str, td: str) -> float:
    """Apply EX and TD ceiling-deltas to a base severity score."""
    return round_half_up(min(10.0, score + agentic_risk_delta(ex=ex, td=td)), 1)


MANDATORY_AGENTIC_METRICS: dict[str, dict[str, tuple[str, str]]] = {
    "EX": EX_VALUES,
    "TD": TD_VALUES,
}

SCORED_AGENTIC_METRICS: dict[str, dict[str, tuple[str, str]]] = {
    "LC": LC_VALUES,
    "CP": CP_VALUES,
    "AP": AP_VALUES,
    "SR": SR_VALUES,
}

# Backward-compatible alias used in tests and macrovector-adjacent code.
SCORED_AI_METRICS = SCORED_AGENTIC_METRICS

AGENTIC_METRICS: dict[str, dict[str, tuple[str, str]]] = {
    **SCORED_AGENTIC_METRICS,
    **MANDATORY_AGENTIC_METRICS,
}

# Backward-compatible alias for parsers and CLI.
AI_METRICS = AGENTIC_METRICS

AGENTIC_METRIC_ORDER: tuple[str, ...] = ("LC", "CP", "AP", "SR", "EX", "TD")
AI_METRIC_ORDER = AGENTIC_METRIC_ORDER

AGENTIC_EFFECT_CLASS_LABELS: dict[str, str] = {
    "A0": "Absent — no agentic amplification beyond CVSS",
    "A1": "Present — agentic factors elevate concern",
    "A2": "Substantial — agentic factors materially worsen impact",
}


@dataclass(frozen=True)
class AIProfile:
    """A parsed Agentic AI Profile. EX and TD adjust the published AIVSS risk score."""

    lc: str = "N"
    cp: str = "N"
    ap: str = "N"
    sr: str = "U"
    ex: str | None = None
    td: str | None = None
    scored_present: bool = True

    def __post_init__(self) -> None:
        for name, value in (("LC", self.lc), ("CP", self.cp), ("AP", self.ap), ("SR", self.sr)):
            if value not in SCORED_AGENTIC_METRICS[name]:
                raise ValueError(
                    f"Illegal value {value!r} for Agentic AI metric {name!r}; "
                    f"expected one of {sorted(SCORED_AGENTIC_METRICS[name])}"
                )
        if self.ex is not None and self.ex not in EX_VALUES:
            raise ValueError(
                f"Illegal value {self.ex!r} for Agentic AI metric 'EX'; "
                f"expected one of {sorted(EX_VALUES)}"
            )
        if self.td is not None and self.td not in TD_VALUES:
            raise ValueError(
                f"Illegal value {self.td!r} for Agentic AI metric 'TD'; "
                f"expected one of {sorted(TD_VALUES)}"
            )

    @property
    def is_absent(self) -> bool:
        """True when no scored AI metric group is present or all are benign."""
        if not self.scored_present:
            return True
        return self.lc == "N" and self.cp == "N" and self.ap == "N" and self.sr == "U"

    def agentic_effect_class(self) -> str:
        """Derive the Agentic Effect Class (A0 / A1 / A2) from scored metrics."""
        return self.effect_class()

    def effect_class(self) -> str:
        """Derive the Agentic Effect Class (A0 / A1 / A2)."""
        if not self.scored_present:
            return "A0"
        if self.ap == "L":
            return "A2"
        if self.lc in ("D", "I") and self.cp == "C":
            return "A2"
        if self.lc == "D" and self.sr == "R":
            return "A2"
        if self.ex == "W" and self.lc in ("D", "I"):
            return "A2"
        if self.is_absent:
            return "A0"
        return "A1"

    def to_vector_fragment(self) -> str:
        """Render as the Agentic AI metric group of a CVSS v4.0 vector."""
        parts: list[str] = []
        if self.scored_present:
            parts.extend(
                [f"LC:{self.lc}", f"CP:{self.cp}", f"AP:{self.ap}", f"SR:{self.sr}"]
            )
        if self.ex is not None:
            parts.append(f"EX:{self.ex}")
        if self.td is not None:
            parts.append(f"TD:{self.td}")
        return "/".join(parts)

    def describe(self) -> dict[str, str]:
        out: dict[str, str] = {}
        if self.scored_present:
            out.update(
                {
                    "LC": f"{self.lc} ({LC_VALUES[self.lc][0]})",
                    "CP": f"{self.cp} ({CP_VALUES[self.cp][0]})",
                    "AP": f"{self.ap} ({AP_VALUES[self.ap][0]})",
                    "SR": f"{self.sr} ({SR_VALUES[self.sr][0]})",
                }
            )
        if self.ex is not None:
            out["EX"] = f"{self.ex} ({EX_VALUES[self.ex][0]})"
        if self.td is not None:
            out["TD"] = f"{self.td} ({TD_VALUES[self.td][0]})"
        return out


def split_ai_vector(vector: str) -> tuple[str, AIProfile | None]:
    """Split a combined vector into its CVSS portion and its AI metric profile.

    Appendix E section 8 extends the CVSS vector with an optional AI metric group,
    e.g. ``CVSS:4.0/.../E:P/LC:D/CP:C/AP:L/SR:R/EX:W/TD:H``. Returns the CVSS-only
    vector string and the Agentic AI Profile, or None when no AI metrics are present.
    """
    cvss_parts: list[str] = []
    found: dict[str, str] = {}
    for part in vector.strip().split("/"):
        key, _, value = part.partition(":")
        if key in AI_METRICS:
            if key in found:
                raise ValueError(f"Duplicate AI metric {key!r}")
            if value not in AI_METRICS[key]:
                raise ValueError(
                    f"Illegal value {value!r} for AI metric {key!r}; "
                    f"expected one of {sorted(AI_METRICS[key])}"
                )
            found[key] = value
        else:
            cvss_parts.append(part)

    if not found:
        return "/".join(cvss_parts), None

    scored_found = [name for name in SCORED_AGENTIC_METRICS if name in found]
    mandatory_found = {name: found[name] for name in MANDATORY_AGENTIC_METRICS if name in found}

    if not scored_found:
        if mandatory_found:
            missing_mandatory = [
                name for name in MANDATORY_AGENTIC_METRICS if name not in mandatory_found
            ]
            if missing_mandatory:
                labels = {
                    "EX": "Extension Surface",
                    "TD": "Traceability Deficit",
                }
                parts = [f"{n} ({labels[n]})" for n in missing_mandatory]
                raise ValueError(
                    "EX and TD are both mandatory in every conformant assessment; "
                    f"missing: {', '.join(parts)}"
                )
            return "/".join(cvss_parts), AIProfile(
                ex=mandatory_found["EX"],
                td=mandatory_found["TD"],
                scored_present=False,
            )
        return "/".join(cvss_parts), None

    missing = [name for name in SCORED_AGENTIC_METRICS if name not in found]
    if missing:
        raise ValueError(
            "An Agentic AI metric group must specify all four scored metrics "
            f"(LC, CP, AP, SR); missing: {', '.join(missing)}"
        )

    for name in MANDATORY_AGENTIC_METRICS:
        if name not in found:
            label = "Extension Surface" if name == "EX" else "Traceability Deficit"
            raise ValueError(
                f"{name} ({label}) is mandatory whenever scored Agentic AI metrics "
                "(LC, CP, AP, SR) are present"
            )

    profile = AIProfile(
        lc=found["LC"],
        cp=found["CP"],
        ap=found["AP"],
        sr=found["SR"],
        ex=found["EX"],
        td=found["TD"],
    )
    return "/".join(cvss_parts), profile
