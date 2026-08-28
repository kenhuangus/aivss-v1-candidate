"""Assembles a complete AIVSS v1.0 assessment report."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .ai_metrics import AIProfile, apply_td_risk, split_ai_vector, td_risk_delta
from .cvss_score import score_cvss_bte
from .decision import ExploitationEvidence, decide
from .macrovector import lookup_aivss, macrovector, parse_cvss_vector
from .priority import compute_priority
from .taxonomy import ASI_TOP_10, normalize_asi

SPEC_VERSION = "1.0"
RUBRIC_VERSION = "1.0.1"
VALID_ASSESSOR_KINDS = frozenset({"human", "scanner", "llm_assisted", "imported"})


@dataclass
class Provenance:
    assessor: str | None = None
    assessor_kind: str = "human"
    tool: str | None = None
    tool_version: str | None = None
    assessed_at: str | None = None

    def __post_init__(self) -> None:
        if self.assessor_kind not in VALID_ASSESSOR_KINDS:
            raise ValueError(
                f"assessor_kind must be one of {sorted(VALID_ASSESSOR_KINDS)}; "
                f"got {self.assessor_kind!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessor": self.assessor,
            "assessor_kind": self.assessor_kind,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "assessed_at": self.assessed_at,
        }


@dataclass
class OrgContext:
    """Level 3 inputs. Optional, organization-internal."""

    business_criticality: str = "medium"
    reach: str = "medium"
    likelihood: float = 0.5


@dataclass
class Assessment:
    finding_id: str
    cvss_vector: str
    asi_category: str
    ai_profile: AIProfile | None = None
    evidence: ExploitationEvidence = field(default_factory=ExploitationEvidence)
    org_context: OrgContext | None = None
    provenance: Provenance = field(default_factory=Provenance)
    publicly_exposed: bool | None = None
    cve_id: str | None = None
    automatable: bool | None = None
    technical_impact: str | None = None
    vulnrichment_automatable: bool | None = None
    vulnrichment_technical_impact: str | None = None
    include_decision: bool = True
    include_priority: bool = False


def assess(a: Assessment) -> dict[str, Any]:
    """Produce a schema-conforming AIVSS v1.0 report object."""
    if not a.finding_id or not a.finding_id.strip():
        raise ValueError("finding_id is required")

    cvss_only, embedded = split_ai_vector(a.cvss_vector)
    profile = a.ai_profile if a.ai_profile is not None else embedded

    if profile is None or profile.td is None:
        raise ValueError(
            "TD (Traceability Deficit) is mandatory in every conformant assessment; "
            "include TD:H, TD:M, or TD:L in the vector or ai_profile"
        )

    metrics = parse_cvss_vector(cvss_only)
    mv = macrovector(metrics)
    cvss_bte = score_cvss_bte(cvss_only)
    ai_class = profile.effect_class() if profile is not None else "A0"
    td = profile.td if profile is not None else "L"
    td_delta = td_risk_delta(td)
    aivss_mode1 = apply_td_risk(cvss_bte, td)

    mode2_raw = lookup_aivss(cvss_only, metrics, ai_class)
    mode2_btea = apply_td_risk(mode2_raw["aivss_btea"], td)
    asi = normalize_asi(a.asi_category)

    combined_vector = cvss_only
    if profile is not None:
        fragment = profile.to_vector_fragment()
        if fragment:
            combined_vector = f"{cvss_only}/{fragment}"

    report: dict[str, Any] = {
        "aivss_version": SPEC_VERSION,
        "rubric_version": RUBRIC_VERSION,
        "finding_id": a.finding_id,
        "risk_category": {"id": asi, "name": ASI_TOP_10[asi]},
        "vector": combined_vector,
        "cvss": {"vector": cvss_only, "macrovector": mv, "cvss_bte": cvss_bte},
        "scores": {
            "mode1_interpretation": {
                "aivss": aivss_mode1,
                "cvss_bte": cvss_bte,
                "td_delta": td_delta,
                "basis": (
                    "AIVSS = min(10, CVSS-BTE + TD_delta); "
                    "LC/CP/AP/SR drive AI Effect Class only"
                ),
                "status": "normative",
            },
            "mode2_macrovector": {
                "aivss_btea": mode2_btea,
                "btea_before_td": mode2_raw["aivss_btea"],
                "promoted_macrovector": mode2_raw["promoted_macrovector"],
                "macrovector_delta": mode2_raw["delta"],
                "td_delta": td_delta,
                "delta": round(mode2_btea - cvss_bte, 1),
                "saturated": mode2_raw["saturated"],
                "status": "provisional -- strawman lookup, pending expert calibration",
            },
        },
        "provenance": a.provenance.to_dict(),
    }

    if profile is not None:
        metrics_out = profile.describe() if profile.scored_present or profile.td is not None else {}
        report["ai_profile"] = {
            "present": profile.scored_present,
            "metrics": metrics_out,
            "vector_fragment": profile.to_vector_fragment(),
            "effect_class": ai_class,
        }
    else:
        report["ai_profile"] = {
            "present": False,
            "metrics": {},
            "vector_fragment": "",
            "effect_class": "A0",
        }

    if a.include_decision:
        if a.publicly_exposed is None:
            raise ValueError(
                "publicly_exposed is required when include_decision is true "
                "(Level 2 conformance)"
            )
        report["decision"] = decide(
            evidence=a.evidence,
            publicly_exposed=a.publicly_exposed,
            ai_class=ai_class,
            td=td,
            automatable=a.automatable,
            technical_impact=a.technical_impact,
            sr=profile.sr if profile and profile.scored_present else None,
            cvss_metrics=metrics,
            cve_id=a.cve_id,
            vulnrichment_automatable=a.vulnrichment_automatable,
            vulnrichment_technical_impact=a.vulnrichment_technical_impact,
        )

    if a.include_priority:
        if a.org_context is None:
            raise ValueError("org_context is required when include_priority is true")
        report["priority"] = compute_priority(
            severity=aivss_mode1,
            business_criticality=a.org_context.business_criticality,
            reach=a.org_context.reach,
            likelihood=a.org_context.likelihood,
        )

    return report


def identity_holds(cvss_vector: str) -> bool:
    """Verify the Appendix E identity rule for one vector."""
    cvss_only, _ = split_ai_vector(cvss_vector)
    metrics = parse_cvss_vector(cvss_only)
    cvss_bte = score_cvss_bte(cvss_only)
    return lookup_aivss(cvss_only, metrics, "A0")["aivss_btea"] == cvss_bte
