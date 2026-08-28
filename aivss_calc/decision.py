"""AIVSS Part III -- Decision Track, aligned to CISA BOD 26-04.

BOD 26-04 (June 10, 2026) revoked BOD 22-01 and BOD 19-02 and replaced
CVSS-severity-driven remediation with a four-variable decision model. CISA
publishes three of the four variables for every CVE ID through the Vulnrichment
Program; the fourth (asset exposure) is supplied by the asset owner.

AIVSS does not fork this model. It consumes it verbatim and adds the Agentic
Effect Class as a fifth, clearly separated decision point. The unmodified BOD timeline
is always reported alongside the AIVSS recommendation so that an FCEB agency can
never mistake an AIVSS overlay for its compliance obligation.

Timeline table transcribed from the CERT/CC SSVC "CISA BOD 26-04 Response Model"
(cisa:BOD2604:1.0.0), the reference BOD 26-04 itself cites for the Automatable
and Technical Impact decision point definitions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

TIMELINE_LABELS: dict[str, str] = {
    "FSU": "Fix on system upgrade",
    "60D": "Remediate within 60 days",
    "14D": "Remediate within 14 days",
    "3D": "Remediate within 3 days",
    "3DF": "Remediate within 3 days and carry out a forensic triage of the asset",
}

# Ordered least to most urgent. Used for Agentic Effect Class escalation.
TIMELINE_URGENCY: tuple[str, ...] = ("FSU", "60D", "14D", "3D", "3DF")

# All 16 rows of BOD 26-04 Table 1, keyed (in_kev, publicly_exposed, automatable,
# technical_impact). Held as data rather than boolean conditions: the fast tier
# requires exposure or automatability in addition to KEV, so hand-written
# conditions such as "KEV and total impact implies 3 days" are wrong for
# (yes, no, no, total), which is 14 days.
BOD_2604_TABLE: dict[tuple[bool, bool, bool, str], str] = {
    (False, False, False, "partial"): "FSU",
    (True, False, False, "partial"): "14D",
    (False, True, False, "partial"): "60D",
    (False, False, True, "partial"): "60D",
    (False, False, False, "total"): "FSU",
    (True, True, False, "partial"): "14D",
    (True, False, True, "partial"): "14D",
    (False, True, True, "partial"): "14D",
    (True, False, False, "total"): "14D",
    (False, True, False, "total"): "14D",
    (False, False, True, "total"): "60D",
    (True, True, True, "partial"): "3D",
    (True, True, False, "total"): "3DF",
    (True, False, True, "total"): "3DF",
    (False, True, True, "total"): "3D",
    (True, True, True, "total"): "3DF",
}


class Exploitation(str, Enum):
    """Exploitation state, resolved by the evidence ladder."""

    ACTIVE = "active"
    ACTIVE_UNVERIFIED = "active_unverified"
    POC = "poc"
    NONE = "none"


# Strict precedence, highest authority first. Replaces the withdrawn
# max(ThM_discrete, ThM_EPSS, ThM_KEV) construction: no transforms, no invented
# probabilities, and no rung that lets a weaker source override a stronger one.
EVIDENCE_LADDER: tuple[tuple[str, str], ...] = (
    ("cisa_kev", "CVE listed in the CISA KEV catalog (authoritative)"),
    ("vulnrichment_active", "CISA Vulnrichment reports Exploitation: active"),
    (
        "observed_local",
        "Exploitation observed and documented by the assessing organization "
        "(non-CVE agentic finding; not CISA-verified)",
    ),
    ("poc", "Public or private proof-of-concept exists"),
    ("none", "No factual exploitation evidence"),
)


@dataclass
class ExploitationEvidence:
    """Inputs to the exploitation evidence ladder."""

    cisa_kev: bool = False
    vulnrichment_active: bool = False
    epss: float | None = None
    epss_date: str | None = None
    observed_local: bool = False
    poc: bool = False

    def __post_init__(self) -> None:
        if self.epss is not None:
            if not 0.0 <= self.epss <= 1.0:
                raise ValueError(f"epss must be in [0.0, 1.0]; got {self.epss}")
            if not self.epss_date:
                raise ValueError(
                    "epss_date is required whenever epss is supplied: EPSS is revised "
                    "daily and an undated score is not reproducible"
                )

    def resolve(self) -> dict[str, object]:
        """Walk the factual exploitation ladder.

        EPSS is recorded alongside the result but does not determine exploitation
        state: it is a calibrated forecast, not a factual exploitation signal, and
        must not outrank documented local observation.
        """
        if self.cisa_kev:
            rung, state = "cisa_kev", Exploitation.ACTIVE
        elif self.vulnrichment_active:
            rung, state = "vulnrichment_active", Exploitation.ACTIVE
        elif self.observed_local:
            rung, state = "observed_local", Exploitation.ACTIVE_UNVERIFIED
        elif self.poc:
            rung, state = "poc", Exploitation.POC
        else:
            rung, state = "none", Exploitation.NONE

        return {
            "rung": rung,
            "rationale": dict(EVIDENCE_LADDER)[rung],
            "state": state.value,
            "authoritative": rung in ("cisa_kev", "vulnrichment_active"),
            "epss": self.epss,
            "epss_date": self.epss_date,
        }


def bod_timeline(
    *,
    in_kev: bool,
    publicly_exposed: bool,
    automatable: bool,
    technical_impact: str,
) -> str:
    """Return the BOD 26-04 Table 1 remediation timeline key."""
    impact = technical_impact.strip().lower()
    if impact not in ("partial", "total"):
        raise ValueError(
            f"technical_impact must be 'partial' or 'total'; got {technical_impact!r}"
        )
    return BOD_2604_TABLE[(bool(in_kev), bool(publicly_exposed), bool(automatable), impact)]


def advance_timeline(timeline: str, steps: int = 1) -> str:
    """Move a timeline toward 3D by ``steps`` tiers (never into 3DF)."""
    if steps <= 0:
        return timeline
    index = TIMELINE_URGENCY.index(timeline)
    ceiling = TIMELINE_URGENCY.index("3D")
    return TIMELINE_URGENCY[min(index + steps, ceiling)]


def escalate(timeline: str, agentic_effect_class: str) -> str:
    """Escalate a timeline by one tier when the Agentic Effect Class is A2.

    Escalation stops at 3D. AIVSS never escalates into 3DF, because the forensic
    triage obligation is a CISA determination tied to KEV listing, not something
    a third-party framework may impose.
    """
    return advance_timeline(timeline, 1) if agentic_effect_class == "A2" else timeline


def decide(
    *,
    evidence: ExploitationEvidence,
    publicly_exposed: bool,
    agentic_effect_class: str = "A0",
    td: str | None = None,
    automatable: bool | None = None,
    technical_impact: str | None = None,
    sr: str | None = None,
    cvss_metrics: dict[str, str] | None = None,
    cve_id: str | None = None,
    vulnrichment_automatable: bool | None = None,
    vulnrichment_technical_impact: str | None = None,
) -> dict[str, object]:
    """Run the five-point decision model.

    BOD 26-04 defaults (automatable=no, technical_impact=total) apply to CVEs
    lacking Vulnrichment metadata. SR and CVSS derivations apply only to findings
    with no CVE and no published Vulnrichment record.
    """
    resolved = evidence.resolve()

    has_cve = bool(cve_id and cve_id.strip())
    has_vulnrichment = (
        vulnrichment_automatable is not None or vulnrichment_technical_impact is not None
    )
    use_agentic_derivation = not has_cve and not has_vulnrichment and not evidence.cisa_kev

    automatable_source = "supplied"
    if automatable is None:
        if vulnrichment_automatable is not None:
            automatable, automatable_source = vulnrichment_automatable, "CISA Vulnrichment"
        elif use_agentic_derivation and sr is not None:
            automatable, automatable_source = sr == "R", "derived from SR (non-CVE finding)"
        else:
            automatable, automatable_source = False, "BOD 26-04 default (no)"

    impact_source = "supplied"
    if technical_impact is None:
        if vulnrichment_technical_impact is not None:
            technical_impact = vulnrichment_technical_impact.strip().lower()
            impact_source = "CISA Vulnrichment"
        elif use_agentic_derivation and cvss_metrics:
            high = any(cvss_metrics.get(m) == "H" for m in ("VC", "VI", "VA"))
            technical_impact = "total" if high else "partial"
            impact_source = "derived from CVSS VC/VI/VA (non-CVE finding)"
        else:
            technical_impact, impact_source = "total", "BOD 26-04 default (total)"
    else:
        technical_impact = technical_impact.strip().lower()

    base = bod_timeline(
        in_kev=bool(evidence.cisa_kev),
        publicly_exposed=publicly_exposed,
        automatable=bool(automatable),
        technical_impact=technical_impact,
    )
    escalation_steps = (1 if agentic_effect_class == "A2" else 0) + (1 if td == "H" else 0)
    recommended = advance_timeline(base, escalation_steps)

    return {
        "exploitation": resolved,
        "decision_points": {
            "in_kev": bool(evidence.cisa_kev),
            "publicly_exposed": bool(publicly_exposed),
            "automatable": bool(automatable),
            "automatable_source": automatable_source,
            "technical_impact": technical_impact,
            "technical_impact_source": impact_source,
            "agentic_effect_class": agentic_effect_class,
            "td": td,
        },
        "bod_2604_timeline": base,
        "bod_2604_label": TIMELINE_LABELS[base],
        "aivss_recommended_timeline": recommended,
        "aivss_recommended_label": TIMELINE_LABELS[recommended],
        "escalated": recommended != base,
        "note": (
            "bod_2604_timeline is the unmodified BOD 26-04 Table 1 result and is the "
            "operative value for FCEB compliance. aivss_recommended_timeline is a "
            "non-binding organizational overlay. TD:H may advance the overlay by one "
            "additional tier because scope of compromise cannot be bounded."
        ),
    }
