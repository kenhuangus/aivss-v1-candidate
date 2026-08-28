"""The AIVSS AI metric group: LC, CP, AP, SR (scored) and TD (mandatory risk factor).

TD implements Agent Untraceability from the original OWASP AIVSS Agentic AI Core
Risks taxonomy. It is required in every conformant assessment but never affects
the numeric severity score.

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

SCORED_AI_METRICS: dict[str, dict[str, tuple[str, str]]] = {
    "LC": LC_VALUES,
    "CP": CP_VALUES,
    "AP": AP_VALUES,
    "SR": SR_VALUES,
}

AI_METRICS: dict[str, dict[str, tuple[str, str]]] = {**SCORED_AI_METRICS, "TD": TD_VALUES}

# Appendix E section 8 fixes this order.
AI_METRIC_ORDER: tuple[str, ...] = ("LC", "CP", "AP", "SR", "TD")

AI_CLASS_LABELS: dict[str, str] = {
    "A0": "None -- AIVSS equals CVSS-BTE",
    "A1": "Present",
    "A2": "Substantial",
}


@dataclass(frozen=True)
class AIProfile:
    """A parsed AI metric profile. TD never affects the numeric score."""

    lc: str = "N"
    cp: str = "N"
    ap: str = "N"
    sr: str = "U"
    td: str | None = None
    scored_present: bool = True

    def __post_init__(self) -> None:
        for name, value in (("LC", self.lc), ("CP", self.cp), ("AP", self.ap), ("SR", self.sr)):
            if value not in AI_METRICS[name]:
                raise ValueError(
                    f"Illegal value {value!r} for AI metric {name!r}; "
                    f"expected one of {sorted(AI_METRICS[name])}"
                )
        if self.td is not None and self.td not in TD_VALUES:
            raise ValueError(
                f"Illegal value {self.td!r} for AI metric 'TD'; "
                f"expected one of {sorted(TD_VALUES)}"
            )

    @property
    def is_absent(self) -> bool:
        """True when no scored AI metric group is present or all are benign."""
        if not self.scored_present:
            return True
        return self.lc == "N" and self.cp == "N" and self.ap == "N" and self.sr == "U"

    def effect_class(self) -> str:
        """Derive the AI Effect Class -- Appendix E section 4."""
        if not self.scored_present:
            return "A0"
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
        """Render as the AI metric group of a CVSS v4.0 vector, in Appendix E order."""
        if not self.scored_present:
            return f"TD:{self.td}" if self.td is not None else ""
        parts = [f"LC:{self.lc}", f"CP:{self.cp}", f"AP:{self.ap}", f"SR:{self.sr}"]
        if self.td is not None:
            parts.append(f"TD:{self.td}")
        return "/".join(parts)

    def describe(self) -> dict[str, str]:
        out = {
            "LC": f"{self.lc} ({LC_VALUES[self.lc][0]})",
            "CP": f"{self.cp} ({CP_VALUES[self.cp][0]})",
            "AP": f"{self.ap} ({AP_VALUES[self.ap][0]})",
            "SR": f"{self.sr} ({SR_VALUES[self.sr][0]})",
        }
        if self.td is not None:
            out["TD"] = f"{self.td} ({TD_VALUES[self.td][0]})"
        return out


def split_ai_vector(vector: str) -> tuple[str, AIProfile | None]:
    """Split a combined vector into its CVSS portion and its AI metric profile.

    Appendix E section 8 extends the CVSS vector with an optional AI metric group,
    e.g. ``CVSS:4.0/.../E:P/LC:D/CP:C/AP:L/SR:R/TD:H``. Returns the CVSS-only
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

    scored_found = [name for name in SCORED_AI_METRICS if name in found]
    if not scored_found:
        if "TD" in found:
            return "/".join(cvss_parts), AIProfile(td=found["TD"], scored_present=False)
        return "/".join(cvss_parts), None

    missing = [name for name in SCORED_AI_METRICS if name not in found]
    if missing:
        raise ValueError(
            "An AI metric group must specify all four scored metrics "
            f"(LC, CP, AP, SR); missing: {', '.join(missing)}"
        )

    if "TD" not in found:
        raise ValueError(
            "TD (Traceability Deficit) is mandatory whenever scored AI metrics "
            "(LC, CP, AP, SR) are present"
        )

    profile = AIProfile(
        lc=found["LC"], cp=found["CP"], ap=found["AP"], sr=found["SR"], td=found.get("TD")
    )
    return "/".join(cvss_parts), profile
