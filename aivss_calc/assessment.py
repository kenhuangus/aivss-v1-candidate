"""Assembles a complete AIVSS 2.0 candidate assessment report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import re
from typing import Any

from .ai_metrics import (
    ADJUSTMENT_STATUS,
    AGENTIC_METRIC_ORDER,
    AGENTIC_METRICS,
    AGENTIC_EFFECT_CLASS_LABELS,
    AIProfile,
    EFFECT_CLASS_STATUS,
    apply_agentic_risk,
    candidate_adjustment,
    ca_risk_delta,
    ex_risk_delta,
    parse_aivss_vector,
    pt_risk_delta,
    split_ai_vector,
    td_risk_delta,
    validate_metric_evidence,
)
from .cvss_score import round_half_up, score_cvss_bte
from .decision import ExploitationEvidence, decide
from .macrovector import lookup_aivss, macrovector, parse_cvss_vector
from .priority import compute_priority
from .taxonomy import ASI_TOP_10, normalize_asi
from .versions import (
    CALCULATOR_VERSION,
    REPORT_SCHEMA_VERSION,
    RUBRIC_VERSION,
    SPEC_VERSION,
    WEIGHT_SET_ID,
)

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
        for name in ("assessor", "tool", "tool_version"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{name} must be a non-empty string or omitted")
        if self.assessed_at is not None:
            if not isinstance(self.assessed_at, str) or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
                r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
                self.assessed_at,
            ):
                raise ValueError("assessed_at must be an RFC 3339 timestamp")
            try:
                parsed = datetime.fromisoformat(self.assessed_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("assessed_at must be an RFC 3339 timestamp") from exc
            if parsed.tzinfo is None:
                raise ValueError(
                    "assessed_at must include time and UTC offset in RFC 3339 format"
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
    """Optional, organization-internal priority inputs."""

    business_criticality: str = "medium"
    reach: str = "medium"
    likelihood: float = 0.5


@dataclass
class Assessment:
    finding_id: str
    cvss_vector: str
    asi_category: str
    title: str | None = None
    summary: str | None = None
    aivss_vector: str | None = None
    ai_profile: AIProfile | None = None
    agentic_applicability: dict[str, Any] = field(default_factory=dict)
    metric_evidence: dict[str, dict[str, Any]] = field(default_factory=dict)
    path_id: str | None = None
    evidence: ExploitationEvidence = field(default_factory=ExploitationEvidence)
    org_context: OrgContext | None = None
    provenance: Provenance = field(default_factory=Provenance)
    publicly_exposed: bool | None = None
    publicly_exposed_source: str | None = None
    decision_data_observed_at: str | None = None
    cve_id: str | None = None
    fceb_bod_2604_scope: bool = False
    automatable: bool | None = None
    technical_impact: str | None = None
    vulnrichment_automatable: bool | None = None
    vulnrichment_technical_impact: str | None = None
    include_decision: bool = True
    include_priority: bool = False
    include_experimental_mode2: bool = False


def assessment_from_payload(payload: dict[str, Any]) -> Assessment:
    """Build an Assessment from an input-schema-conforming mapping."""
    org = payload.get("org_context")
    return Assessment(
        finding_id=payload["finding_id"],
        path_id=payload["path_id"],
        title=payload.get("title"),
        summary=payload.get("summary"),
        cvss_vector=payload["cvss_vector"],
        aivss_vector=payload["aivss_vector"],
        asi_category=payload["risk_category"],
        agentic_applicability=dict(payload["agentic_applicability"]),
        metric_evidence=dict(payload["metric_evidence"]),
        evidence=ExploitationEvidence(**dict(payload.get("evidence", {}))),
        org_context=OrgContext(**org) if org else None,
        provenance=Provenance(**dict(payload.get("provenance", {}))),
        publicly_exposed=payload.get("publicly_exposed"),
        publicly_exposed_source=payload.get("publicly_exposed_source"),
        decision_data_observed_at=payload.get("decision_data_observed_at"),
        cve_id=payload.get("cve_id"),
        fceb_bod_2604_scope=payload.get("fceb_bod_2604_scope", False),
        automatable=payload.get("automatable"),
        technical_impact=payload.get("technical_impact"),
        vulnrichment_automatable=payload.get("vulnrichment_automatable"),
        vulnrichment_technical_impact=payload.get("vulnrichment_technical_impact"),
        include_decision=payload.get("include_decision", True),
        include_priority=payload.get("include_priority", False),
        include_experimental_mode2=payload.get("include_experimental_mode2", False),
    )


def assess(a: Assessment) -> dict[str, Any]:
    """Produce a schema-conforming AIVSS candidate report for one exploit path."""
    if not isinstance(a.finding_id, str) or not a.finding_id.strip():
        raise ValueError("finding_id is required")
    if not isinstance(a.path_id, str) or not a.path_id.strip():
        raise ValueError("path_id is required to identify one coherent exploit path")
    if a.finding_id != a.finding_id.strip() or a.path_id != a.path_id.strip():
        raise ValueError(
            "finding_id and path_id must not contain surrounding whitespace"
        )
    for name in ("title", "summary"):
        value = getattr(a, name)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ValueError(f"{name} must be a non-empty string or omitted")
    for name in (
        "fceb_bod_2604_scope",
        "include_decision",
        "include_priority",
        "include_experimental_mode2",
    ):
        if type(getattr(a, name)) is not bool:
            raise ValueError(f"{name} must be true or false")
    if not isinstance(a.metric_evidence, dict):
        raise ValueError("metric_evidence must be an object")
    applicability = a.agentic_applicability
    if not isinstance(applicability, dict) or set(applicability) != {
        "model_directed_goal_pursuit",
        "action_selection_or_sequencing",
        "rationale",
        "evidence_refs",
    }:
        raise ValueError("agentic_applicability must contain the four required fields")
    for name in (
        "model_directed_goal_pursuit",
        "action_selection_or_sequencing",
    ):
        if type(applicability[name]) is not bool:
            raise ValueError(f"agentic_applicability.{name} must be true or false")
        if not applicability[name]:
            raise ValueError(
                "AIVSS is not applicable unless the assessed system performs "
                "model-directed goal pursuit and action selection or sequencing"
            )
    if (
        not isinstance(applicability["rationale"], str)
        or not applicability["rationale"].strip()
        or not isinstance(applicability["evidence_refs"], list)
        or not applicability["evidence_refs"]
        or any(
            not isinstance(ref, str) or not ref.strip()
            for ref in applicability["evidence_refs"]
        )
    ):
        raise ValueError(
            "agentic_applicability requires a non-empty rationale and evidence_refs"
        )
    if not isinstance(a.provenance, Provenance):
        raise ValueError("provenance must be a Provenance record")

    cvss_only, embedded = split_ai_vector(a.cvss_vector)
    profile_sources = sum(
        source is not None for source in (embedded, a.aivss_vector, a.ai_profile)
    )
    if profile_sources > 1:
        raise ValueError(
            "Provide the AIVSS profile exactly once: aivss_vector, ai_profile, "
            "or two-vector display form"
        )
    profile = (
        a.ai_profile
        if a.ai_profile is not None
        else parse_aivss_vector(a.aivss_vector)
        if a.aivss_vector is not None
        else embedded
    )
    if profile is None:
        raise ValueError(
            "All eight AIVSS metrics are required in a separate current-version "
            "AIVSS extension vector"
        )
    validate_metric_evidence(profile, a.metric_evidence)
    if a.provenance.assessed_at is None:
        raise ValueError(
            "provenance.assessed_at is required as an RFC 3339 evidence timestamp"
        )

    metrics = parse_cvss_vector(cvss_only)
    mv = macrovector(metrics)
    cvss_bte = score_cvss_bte(cvss_only)
    ai_class = profile.effect_class()
    ex, pt, ca, td = profile.ex, profile.pt, profile.ca, profile.td
    adjustment = None
    if profile.complete:
        adjustment = candidate_adjustment(cvss_bte, ex=ex, pt=pt, ca=ca, td=td)

    asi = normalize_asi(a.asi_category)

    report: dict[str, Any] = {
        "aivss_version": SPEC_VERSION,
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "rubric_version": RUBRIC_VERSION,
        "calculator_version": CALCULATOR_VERSION,
        "specification_status": "candidate",
        "finding_id": a.finding_id,
        "path_id": a.path_id,
        "risk_category": {"id": asi, "name": ASI_TOP_10[asi]},
        "agentic_applicability": dict(applicability),
        "cvss": {"vector": cvss_only, "macrovector": mv, "cvss_bte": cvss_bte},
        "scores": {
            "mode1_interpretation": {
                "aivss": cvss_bte,
                "cvss_bte": cvss_bte,
                "status": "normative",
                "basis": (
                    "Mode 1: AIVSS = CVSS-BTE. Agentic AI metrics are parallel "
                    "metadata and do not modify the severity number."
                ),
            },
            "candidate_adjusted": {
                "aivss": adjustment.value if adjustment else None,
                "raw_aivss": adjustment.raw_value if adjustment else None,
                "cvss_bte": cvss_bte,
                "ex_delta": ex_risk_delta(ex) if adjustment else None,
                "pt_delta": pt_risk_delta(pt) if adjustment else None,
                "ca_delta": ca_risk_delta(ca) if adjustment else None,
                "td_delta": td_risk_delta(td) if adjustment else None,
                "agentic_risk_delta": adjustment.delta if adjustment else None,
                "capped": adjustment.capped if adjustment else None,
                "zero_impact_invariant_applied": (
                    cvss_bte == 0.0 if adjustment else None
                ),
                "basis": (
                    "Candidate only: AIVSS = min(10, CVSS-BTE + EX + PT + CA + TD); "
                    "a zero-impact CVSS result remains zero"
                ),
                "status": ADJUSTMENT_STATUS if adjustment else "incomplete",
                "weight_set": WEIGHT_SET_ID,
                "calibration_status": "not empirically calibrated",
            },
        },
        "provenance": a.provenance.to_dict(),
    }
    if a.title is not None:
        report["title"] = a.title
    if a.summary is not None:
        report["summary"] = a.summary

    report["agentic_ai_profile"] = {
        "vector": profile.to_vector(),
        "metrics": {
            name: {
                "value": getattr(profile, name.lower()),
                "label": AGENTIC_METRICS[name][getattr(profile, name.lower())][0],
                "evidence": dict(a.metric_evidence[name]),
            }
            for name in AGENTIC_METRIC_ORDER
        },
        "complete": profile.complete,
        "agentic_effect_class": ai_class,
        "agentic_effect_class_label": AGENTIC_EFFECT_CLASS_LABELS[ai_class],
        "agentic_effect_class_status": EFFECT_CLASS_STATUS,
    }

    if a.include_experimental_mode2:
        if not profile.complete:
            report["scores"]["experimental_macrovector"] = {
                "status": "incomplete",
                "aivss_btea": None,
            }
        else:
            mode2_raw = lookup_aivss(cvss_only, metrics, ai_class)
            mode2_btea = apply_agentic_risk(
                mode2_raw["aivss_btea"], ex=ex, pt=pt, ca=ca, td=td
            )
            report["scores"]["experimental_macrovector"] = {
                "aivss_btea": mode2_btea,
                "btea_before_agentic_risk": mode2_raw["aivss_btea"],
                "promoted_macrovector": mode2_raw["promoted_macrovector"],
                "macrovector_delta": mode2_raw["delta"],
                "agentic_risk_delta": adjustment.delta,
                "delta": round_half_up(mode2_btea - cvss_bte, 1),
                "saturated": mode2_raw["saturated"],
                "status": "experimental-uncalibrated",
            }

    if a.include_decision:
        if a.publicly_exposed is None:
            raise ValueError(
                "publicly_exposed is required when include_decision is true"
            )
        report["decision"] = decide(
            evidence=a.evidence,
            publicly_exposed=a.publicly_exposed,
            publicly_exposed_source=a.publicly_exposed_source,
            decision_data_observed_at=a.decision_data_observed_at,
            agentic_effect_class=ai_class,
            td=td,
            automatable=a.automatable,
            technical_impact=a.technical_impact,
            cve_id=a.cve_id,
            fceb_bod_2604_scope=a.fceb_bod_2604_scope,
            vulnrichment_automatable=a.vulnrichment_automatable,
            vulnrichment_technical_impact=a.vulnrichment_technical_impact,
        )

    if a.include_priority:
        if a.org_context is None:
            raise ValueError("org_context is required when include_priority is true")
        if adjustment is None:
            raise ValueError(
                "priority cannot be calculated while any AIVSS metric is X"
            )
        report["priority"] = compute_priority(
            severity=adjustment.value,
            business_criticality=a.org_context.business_criticality,
            reach=a.org_context.reach,
            likelihood=a.org_context.likelihood,
        )

    return report


def identity_holds(cvss_vector: str) -> bool:
    """Verify that A0 leaves the experimental MacroVector unchanged."""
    cvss_only, _ = split_ai_vector(cvss_vector)
    metrics = parse_cvss_vector(cvss_only)
    cvss_bte = score_cvss_bte(cvss_only)
    return lookup_aivss(cvss_only, metrics, "A0")["aivss_btea"] == cvss_bte
