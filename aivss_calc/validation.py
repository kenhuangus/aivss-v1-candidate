"""Syntactic and semantic validation for AIVSS candidate artifacts."""

from __future__ import annotations

import json
from pathlib import Path
import sysconfig
from typing import Any

import jsonschema

from .ai_metrics import (
    AGENTIC_EFFECT_CLASS_LABELS,
    AGENTIC_METRIC_ORDER,
    AGENTIC_METRICS,
    ca_risk_delta,
    candidate_adjustment,
    ex_risk_delta,
    parse_aivss_vector,
    pt_risk_delta,
    td_risk_delta,
    validate_metric_evidence,
)
from .assessment import Provenance
from .cvss_score import round_half_up, score_cvss_bte
from .decision import (
    EVIDENCE_LADDER,
    TIMELINE_LABELS,
    ExploitationEvidence,
    advance_timeline,
    bod_timeline,
    decide,
)
from .macrovector import lookup_aivss, macrovector, parse_cvss_vector
from .priority import compute_priority
from .taxonomy import ASI_TOP_10

_SOURCE_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
_INSTALLED_SCHEMA_DIR = Path(sysconfig.get_path("data")) / "share" / "aivss" / "schemas"
SCHEMA_DIR = (
    _SOURCE_SCHEMA_DIR
    if (_SOURCE_SCHEMA_DIR / "aivss-report-v2.0.json").is_file()
    else _INSTALLED_SCHEMA_DIR
)
INPUT_SCHEMA = SCHEMA_DIR / "aivss-assessment-input-v2.0.json"
REPORT_SCHEMA = SCHEMA_DIR / "aivss-report-v2.0.json"


def _schema(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_assessment_input(payload: dict[str, Any]) -> None:
    """Validate input shape plus vector and evidence semantics."""
    jsonschema.validate(payload, _schema(INPUT_SCHEMA))
    for name in ("finding_id", "path_id"):
        if payload[name] != payload[name].strip():
            raise ValueError(f"{name} must not contain surrounding whitespace")
    for name in ("title", "summary"):
        if name in payload and not payload[name].strip():
            raise ValueError(f"{name} must not be whitespace-only")
    applicability = payload["agentic_applicability"]
    if not applicability["rationale"].strip() or any(
        not ref.strip() for ref in applicability["evidence_refs"]
    ):
        raise ValueError("agentic_applicability evidence must not be whitespace-only")
    parse_cvss_vector(payload["cvss_vector"])
    score_cvss_bte(payload["cvss_vector"])
    profile = parse_aivss_vector(payload["aivss_vector"])
    validate_metric_evidence(profile, payload["metric_evidence"])
    Provenance(**payload["provenance"])
    evidence = ExploitationEvidence(**payload.get("evidence", {}))
    if payload.get("include_decision", True):
        decide(
            evidence=evidence,
            publicly_exposed=payload["publicly_exposed"],
            publicly_exposed_source=payload["publicly_exposed_source"],
            decision_data_observed_at=payload["decision_data_observed_at"],
            agentic_effect_class=profile.effect_class(),
            td=profile.td,
            automatable=payload.get("automatable"),
            technical_impact=payload.get("technical_impact"),
            cve_id=payload.get("cve_id"),
            fceb_bod_2604_scope=payload.get("fceb_bod_2604_scope", False),
            vulnrichment_automatable=payload.get("vulnrichment_automatable"),
            vulnrichment_technical_impact=payload.get("vulnrichment_technical_impact"),
        )


def validate_report(report: dict[str, Any]) -> None:
    """Validate JSON shape and cross-field scoring invariants."""
    jsonschema.validate(report, _schema(REPORT_SCHEMA))
    Provenance(**report["provenance"])
    for name in ("title", "summary"):
        if name in report and not report[name].strip():
            raise ValueError(f"{name} must not be whitespace-only")
    applicability = report["agentic_applicability"]
    if not applicability["rationale"].strip() or any(
        not ref.strip() for ref in applicability["evidence_refs"]
    ):
        raise ValueError("agentic_applicability evidence must not be whitespace-only")

    asi = report["risk_category"]
    if ASI_TOP_10[asi["id"]] != asi["name"]:
        raise ValueError("risk_category name does not match its ASI identifier")

    cvss = report["cvss"]
    expected_cvss = score_cvss_bte(cvss["vector"])
    if cvss["cvss_bte"] != expected_cvss:
        raise ValueError("cvss_bte does not match the CVSS vector")
    expected_macrovector = macrovector(parse_cvss_vector(cvss["vector"]))
    if cvss["macrovector"] != expected_macrovector:
        raise ValueError("macrovector does not match the CVSS vector")

    extension = report["agentic_ai_profile"]
    profile = parse_aivss_vector(extension["vector"])
    for name in AGENTIC_METRIC_ORDER:
        value = getattr(profile, name.lower())
        if extension["metrics"][name]["value"] != value:
            raise ValueError(f"{name} does not match the AIVSS vector")
        if extension["metrics"][name]["label"] != AGENTIC_METRICS[name][value][0]:
            raise ValueError(f"{name} label does not match its value")
    validate_metric_evidence(
        profile,
        {
            name: extension["metrics"][name]["evidence"]
            for name in AGENTIC_METRIC_ORDER
        },
    )
    if extension["complete"] != profile.complete:
        raise ValueError("profile complete flag does not match metric values")
    if extension["agentic_effect_class"] != profile.effect_class():
        raise ValueError("agentic_effect_class does not match the AIVSS vector")
    if (
        extension["agentic_effect_class_label"]
        != AGENTIC_EFFECT_CLASS_LABELS[profile.effect_class()]
    ):
        raise ValueError("agentic_effect_class_label does not match the class")
    if extension["agentic_effect_class_status"] != "candidate-unvalidated":
        raise ValueError("agentic_effect_class_status must disclose candidate validity")

    score = report["scores"]["candidate_adjusted"]
    if profile.complete:
        expected = candidate_adjustment(
            expected_cvss,
            ex=profile.ex,
            pt=profile.pt,
            ca=profile.ca,
            td=profile.td,
        )
        checks = {
            "aivss": expected.value,
            "raw_aivss": expected.raw_value,
            "cvss_bte": expected_cvss,
            "ex_delta": ex_risk_delta(profile.ex),
            "pt_delta": pt_risk_delta(profile.pt),
            "ca_delta": ca_risk_delta(profile.ca),
            "td_delta": td_risk_delta(profile.td),
            "agentic_risk_delta": expected.delta,
            "capped": expected.capped,
            "zero_impact_invariant_applied": expected_cvss == 0.0,
            "status": "experimental-uncalibrated",
        }
        for key, value in checks.items():
            if score[key] != value:
                raise ValueError(f"{key} does not match the candidate calculation")
    else:
        if any(
            score[key] is not None
            for key in (
                "aivss",
                "raw_aivss",
                "ex_delta",
                "pt_delta",
                "ca_delta",
                "td_delta",
                "agentic_risk_delta",
                "capped",
                "zero_impact_invariant_applied",
            )
        ):
            raise ValueError("incomplete profiles must not emit a candidate score")
        if score["status"] != "incomplete":
            raise ValueError("incomplete profile has the wrong score status")
        if score["cvss_bte"] != expected_cvss:
            raise ValueError("candidate cvss_bte does not match the CVSS vector")

    if experiment := report["scores"].get("experimental_macrovector"):
        if not profile.complete:
            if experiment != {"status": "incomplete", "aivss_btea": None}:
                raise ValueError("incomplete MacroVector experiment emitted values")
        else:
            raw_experiment = lookup_aivss(
                cvss["vector"],
                parse_cvss_vector(cvss["vector"]),
                profile.effect_class(),
            )
            expected_adjusted = candidate_adjustment(
                raw_experiment["aivss_btea"],
                ex=profile.ex,
                pt=profile.pt,
                ca=profile.ca,
                td=profile.td,
            )
            expected_fields = {
                "aivss_btea": expected_adjusted.value,
                "btea_before_agentic_risk": raw_experiment["aivss_btea"],
                "promoted_macrovector": raw_experiment["promoted_macrovector"],
                "macrovector_delta": raw_experiment["delta"],
                "agentic_risk_delta": expected_adjusted.delta,
                "delta": round_half_up(expected_adjusted.value - expected_cvss, 1),
                "saturated": raw_experiment["saturated"],
                "status": "experimental-uncalibrated",
            }
            if experiment != expected_fields:
                raise ValueError("MacroVector experiment does not match its inputs")

    if decision := report.get("decision"):
        recommended = decision["aivss_recommended_timeline"]
        branch_fields = {
            "cisa_bod_26_04": {
                "bod_2604_timeline",
                "bod_2604_label",
                "forensic_triage_required",
            },
            "informative_bod_26_04_cve_guidance": {
                "bod_2604_guidance_timeline",
                "bod_2604_guidance_label",
                "forensic_triage_indicated",
            },
            "informative_bod_26_04_analogy": {
                "bod_2604_analogy_timeline",
                "bod_2604_analogy_label",
                "forensic_triage_indicated",
            },
        }
        allowed_branch_fields = branch_fields[decision["decision_basis"]]
        all_branch_fields = set().union(*branch_fields.values())
        if any(key in decision for key in all_branch_fields - allowed_branch_fields):
            raise ValueError(
                "decision contains fields from the wrong BOD result branch"
            )
        if decision["compliance_applicable"]:
            base_key = "bod_2604_timeline"
            label_key = "bod_2604_label"
        elif decision["decision_basis"] == "informative_bod_26_04_cve_guidance":
            base_key = "bod_2604_guidance_timeline"
            label_key = "bod_2604_guidance_label"
        else:
            base_key = "bod_2604_analogy_timeline"
            label_key = "bod_2604_analogy_label"
        points = decision["decision_points"]
        exploitation = decision["exploitation"]
        rung = exploitation["rung"]
        state_by_rung = {
            "cisa_kev": ("known_exploited", True),
            "vulnrichment_active": ("active_reported", True),
            "observed_local": ("active_observed_local", False),
            "poc": ("poc", False),
            "none": ("no_evidence_supplied", False),
        }
        expected_state, expected_authoritative = state_by_rung[rung]
        if exploitation["state"] != expected_state:
            raise ValueError("exploitation state does not match its evidence rung")
        if exploitation["authoritative"] != expected_authoritative:
            raise ValueError("exploitation authority does not match its evidence rung")
        if exploitation["rationale"] != dict(EVIDENCE_LADDER)[rung]:
            raise ValueError("exploitation rationale does not match its evidence rung")
        ExploitationEvidence(
            epss=exploitation["epss"], epss_date=exploitation["epss_date"]
        )
        if points["in_kev"] != (rung == "cisa_kev"):
            raise ValueError("KEV decision point does not match exploitation evidence")
        sources = {
            points["automatable_source"],
            points["technical_impact_source"],
        }
        if decision["cve_id"] is None and sources != {"supplied"}:
            raise ValueError("non-CVE analogies must use explicitly supplied inputs")
        if points["in_kev"] and any("default" in source for source in sources):
            raise ValueError(
                "KEV decision points must not use missing-metadata defaults"
            )
        if points["agentic_effect_class"] != profile.effect_class():
            raise ValueError("decision class does not match the AIVSS profile")
        if points["td"] != profile.td:
            raise ValueError("decision TD does not match the AIVSS profile")
        expected_base = bod_timeline(
            in_kev=points["in_kev"],
            publicly_exposed=points["publicly_exposed"],
            automatable=points["automatable"],
            technical_impact=points["technical_impact"],
        )
        if decision[base_key] != expected_base:
            raise ValueError("BOD timeline does not match its decision points")
        if decision[label_key] != TIMELINE_LABELS[expected_base]:
            raise ValueError("BOD timeline label does not match its key")
        overlay_complete = (
            points["agentic_effect_class"] != "AX" and points["td"] != "X"
        )
        if overlay_complete:
            triggered = points["agentic_effect_class"] == "A2"
            expected_recommended = advance_timeline(
                expected_base, 1 if triggered else 0
            )
            if decision["overlay_status"] != "experimental-uncalibrated":
                raise ValueError("complete overlay has the wrong status")
            if decision["overlay_triggered"] != triggered:
                raise ValueError("overlay_triggered does not match A2 SSVC extension")
            if recommended != expected_recommended:
                raise ValueError("AIVSS timeline does not match the overlay rule")
            if decision["aivss_recommended_label"] != TIMELINE_LABELS[recommended]:
                raise ValueError("AIVSS timeline label does not match its key")
            if decision["escalated"] != (expected_recommended != expected_base):
                raise ValueError("escalated does not match the timeline change")
        else:
            if decision["overlay_status"] != "incomplete":
                raise ValueError("unknown class or TD must make the overlay incomplete")
            if any(
                decision[key] is not None
                for key in (
                    "aivss_recommended_timeline",
                    "aivss_recommended_label",
                    "overlay_triggered",
                    "escalated",
                    "aivss_recommended_forensic_triage_indicated",
                )
            ):
                raise ValueError("incomplete overlay must withhold its recommendation")
        triage = decision[base_key] == "3DF"
        triage_key = (
            "forensic_triage_required"
            if decision["compliance_applicable"]
            else "forensic_triage_indicated"
        )
        if decision[triage_key] != triage:
            raise ValueError("forensic triage flag does not match the BOD result")
        if overlay_complete:
            if (
                decision["aivss_recommended_forensic_triage_indicated"]
                != triage
            ):
                raise ValueError(
                    "the AIVSS overlay changed a forensic-triage requirement"
                )

    if priority := report.get("priority"):
        candidate_value = report["scores"]["candidate_adjusted"]["aivss"]
        if candidate_value is None:
            raise ValueError("priority must not be emitted without a candidate score")
        terms = priority["terms"]
        inverse_levels = {1.0: "high", 0.65: "medium", 0.35: "low"}
        if terms["severity_norm"] != round(candidate_value / 10.0, 4):
            raise ValueError("priority severity does not match the candidate score")
        expected_priority = compute_priority(
            severity=candidate_value,
            business_criticality=inverse_levels[terms["business_criticality"]],
            reach=inverse_levels[terms["reach"]],
            likelihood=terms["likelihood"],
        )
        if priority != expected_priority:
            raise ValueError("priority does not match its reported terms")
