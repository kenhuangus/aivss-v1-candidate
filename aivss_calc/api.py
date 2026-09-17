"""JSON-friendly entry points shared by the CLI and the web calculator.

Every function takes and returns plain Python values so the same code serves
the command line, the local demo server, and the in-browser (Pyodide) page.
"""

from __future__ import annotations

import json
from typing import Any

from .ai_metrics import (
    AGENTIC_EFFECT_CLASS_LABELS,
    AGENTIC_METRIC_NAMES,
    AGENTIC_METRIC_ORDER,
    AGENTIC_METRIC_SUMMARIES,
    AGENTIC_METRICS,
    ASSURANCE_AGENTIC_METRICS,
    CLASSIFYING_AGENTIC_METRICS,
    EFFECT_CLASS_STATUS,
    AIProfile,
    parse_aivss_vector,
    split_ai_vector,
)
from .cvss_metrics import CVSS_GROUP_INFO, cvss_metric_info
from .cvss_score import score_cvss_bte, severity_rating
from .decision import TIMELINE_LABELS, TIMELINE_URGENCY, ExploitationEvidence, decide
from .macrovector import (
    BASE_METRICS,
    ENV_REQUIREMENT_METRICS,
    MODIFIED_METRICS,
    THREAT_METRICS,
    macrovector,
    parse_cvss_vector,
)
from .scenarios import SCENARIOS
from .taxonomy import ASI_TOP_10
from .versions import CALCULATOR_VERSION, RUBRIC_VERSION, SPEC_VERSION

# Plain-language help for the Level 2 decision inputs and the result panel.
DECISION_INPUT_INFO: dict[str, dict[str, Any]] = {
    "enabled": {
        "summary": (
            "Adds the Level 2 decision track: the unmodified SSVC / BOD 26-04 "
            "timeline plus the non-binding AIVSS overlay."
        ),
    },
    "publicly_exposed": {
        "summary": "Is the affected asset reachable from the public internet?",
        "values": {
            "true": "Reachable from the public internet.",
            "false": "Only reachable from inside the network or another trust boundary.",
        },
    },
    "publicly_exposed_source": {
        "summary": (
            "Where the exposure fact comes from — an asset inventory, an external "
            "scan, or similar. Recorded with the decision; it is never guessed."
        ),
    },
    "automatable": {
        "summary": (
            "Can reconnaissance, weaponisation, delivery and exploitation all be "
            "reliably automated across many targets (SSVC Automatable)?"
        ),
        "values": {
            "true": "An attacker can script the whole chain and run it at scale.",
            "false": "Some step needs human judgement or target-specific work.",
        },
    },
    "technical_impact": {
        "summary": "How much control successful exploitation hands the attacker (SSVC Technical Impact).",
        "values": {
            "partial": "Limited control or information; the attacker cannot fully govern the component.",
            "total": "Full control of the component's behaviour, or all of its information.",
        },
    },
    "evidence": {
        "summary": (
            "The strongest factual exploitation evidence you hold. A stronger rung "
            "always outranks a weaker one; EPSS is never a rung."
        ),
        "values": {
            "none": "No affirmative exploitation evidence was supplied.",
            "poc": "A public or private proof of concept exists.",
            "observed_local": (
                "Your organisation observed and documented exploitation. Suitable for "
                "non-CVE agentic findings; not CISA-verified."
            ),
        },
    },
    "cve_id": {
        "summary": (
            "The CVE ID, if this finding has one. KEV, Vulnrichment and BOD "
            "compliance results all require it."
        ),
    },
    "kev": {
        "summary": (
            "Is the CVE listed in CISA's Known Exploited Vulnerabilities catalog? "
            "It must be answered explicitly for a CVE decision."
        ),
        "values": {
            "true": "Listed in KEV — the authoritative top rung of the evidence ladder.",
            "false": "Not listed in KEV.",
        },
    },
    "fceb_bod_2604_scope": {
        "summary": (
            "Tick only for a US federal civilian (FCEB) asset within the scope of BOD "
            "26-04. The BOD timeline then becomes a compliance obligation instead of "
            "informative guidance."
        ),
    },
}

RESULT_INFO: dict[str, str] = {
    "severity": (
        "Normative AIVSS severity: the CVSS v4.0 Base + Threat + Environmental score. "
        "Agentic metrics never add to this number."
    ),
    "severity_rating": "The CVSS v4.0 qualitative band this score falls in.",
    "effect_class": (
        "Ordinal class derived from LC, CP, AP and SR. Only A2 can trigger the "
        "remediation overlay, and no class changes the severity number."
    ),
    "macrovector": (
        "The CVSS v4.0 equivalence class (EQ1-EQ6) this vector belongs to. The score "
        "is interpolated within the class, so it is usually below the class ceiling."
    ),
    "bod_baseline": (
        "The unmodified SSVC / BOD 26-04 outcome. It is always reported alongside the "
        "AIVSS recommendation."
    ),
    "aivss_recommendation": (
        "The AIVSS candidate overlay: the baseline advanced one tier when the Effect "
        "Class is A2. Non-binding and experimental-uncalibrated."
    ),
}

PROFILE_NOTE = (
    "Normative AIVSS severity equals CVSS-BTE. "
    "LC/CP/AP/SR determine the ordinal Agentic Effect Class; "
    "EX/PT/CA/TD are descriptive profile metadata."
)


def profile_report(cvss_vector: str, profile: AIProfile) -> dict[str, Any]:
    """Score a CVSS v4.0 vector and describe its Agentic AI profile."""
    metrics = parse_cvss_vector(cvss_vector)
    score = score_cvss_bte(cvss_vector)
    return {
        "mode": "interpretation",
        "status": "normative",
        "cvss_vector": cvss_vector,
        "aivss_vector": profile.to_vector(),
        "macrovector": macrovector(metrics),
        "cvss_bte": score,
        "aivss": score,
        "severity_rating": severity_rating(score),
        "note": PROFILE_NOTE,
        "agentic_ai_profile": profile.describe(),
        "agentic_effect_class": profile.agentic_effect_class(),
        "agentic_effect_class_status": EFFECT_CLASS_STATUS,
    }


def profile_from_vectors(cvss_vector: str, aivss_vector: str) -> dict[str, Any]:
    """Score a CVSS vector paired with a separate AIVSS extension vector."""
    cvss_only, embedded = split_ai_vector(cvss_vector)
    if embedded is not None:
        raise ValueError("pass the AIVSS vector separately from the CVSS vector")
    return profile_report(cvss_only, parse_aivss_vector(aivss_vector))


def decision_report(
    *,
    evidence: ExploitationEvidence,
    vector: str | None = None,
    agentic_effect_class: str | None = None,
    **decision_inputs: Any,
) -> dict[str, Any]:
    """Run the SSVC/BOD decision, taking class and TD from a vector if given."""
    effect_class = agentic_effect_class or "A0"
    td = None
    if vector:
        _, embedded = split_ai_vector(vector)
        if embedded is not None:
            td = embedded.td
            effect_class = embedded.agentic_effect_class()
    return decide(
        evidence=evidence,
        agentic_effect_class=effect_class,
        td=td,
        **decision_inputs,
    )


def rubric() -> dict[str, Any]:
    """Exhaustive value sets and definitions for all eight Agentic AI metrics."""
    metrics: dict[str, dict[str, dict[str, str]]] = {}
    for name in AGENTIC_METRIC_ORDER:
        metrics[name] = {
            code: {"label": label, "summary": definition}
            for code, (label, definition) in AGENTIC_METRICS[name].items()
        }
    return {
        "rubric_version": RUBRIC_VERSION,
        "reference": "docs/METRIC-RUBRIC.md",
        "classifying_metrics": list(CLASSIFYING_AGENTIC_METRICS),
        "assurance_metrics": list(ASSURANCE_AGENTIC_METRICS),
        "metrics": metrics,
    }


def calculator_catalog() -> dict[str, Any]:
    """Everything the web calculator needs to render its form and presets."""
    return {
        "versions": {
            "spec": SPEC_VERSION,
            "calculator": CALCULATOR_VERSION,
            "rubric": RUBRIC_VERSION,
        },
        "rubric": rubric(),
        "metric_names": dict(AGENTIC_METRIC_NAMES),
        "metric_summaries": dict(AGENTIC_METRIC_SUMMARIES),
        "effect_classes": dict(AGENTIC_EFFECT_CLASS_LABELS),
        "effect_class_status": EFFECT_CLASS_STATUS,
        "cvss_metric_info": cvss_metric_info(),
        "cvss_groups": {k: dict(v) for k, v in CVSS_GROUP_INFO.items()},
        "decision_inputs": {
            key: {inner: value for inner, value in info.items()}
            for key, info in DECISION_INPUT_INFO.items()
        },
        "result_info": dict(RESULT_INFO),
        "cvss_metrics": {
            "base": {k: list(v) for k, v in BASE_METRICS.items()},
            "threat": {k: list(v) for k, v in THREAT_METRICS.items()},
            "requirements": {k: list(v) for k, v in ENV_REQUIREMENT_METRICS.items()},
            "modified": {k: list(v) for k, v in MODIFIED_METRICS.items()},
        },
        "timelines": {key: TIMELINE_LABELS[key] for key in TIMELINE_URGENCY},
        "presets": [
            {
                "id": s["risk_category"],
                "name": ASI_TOP_10[s["risk_category"]],
                "title": s["title"],
                "summary": s["summary"],
                "cvss_vector": s["cvss_vector"],
                "aivss_vector": s["aivss_vector"],
                "publicly_exposed": s["publicly_exposed"],
                "automatable": s["automatable"],
                "technical_impact": s["technical_impact"],
                "evidence": dict(s["evidence"]),
            }
            for s in SCENARIOS
        ],
    }


def _web_decision(request: dict[str, Any]) -> dict[str, Any]:
    evidence = request.get("evidence") or {}
    return decision_report(
        evidence=ExploitationEvidence(
            cisa_kev=evidence.get("cisa_kev"),
            vulnrichment_active=evidence.get("vulnrichment_active", False),
            epss=evidence.get("epss"),
            epss_date=evidence.get("epss_date"),
            observed_local=evidence.get("observed_local", False),
            poc=evidence.get("poc", False),
        ),
        vector=f"{request['cvss_vector']} {request['aivss_vector']}",
        publicly_exposed=request.get("publicly_exposed"),
        publicly_exposed_source=request.get("publicly_exposed_source"),
        decision_data_observed_at=request.get("decision_data_observed_at"),
        automatable=request.get("automatable"),
        technical_impact=request.get("technical_impact"),
        cve_id=request.get("cve_id"),
        fceb_bod_2604_scope=request.get("fceb_bod_2604_scope", False),
        vulnrichment_automatable=request.get("vulnrichment_automatable"),
        vulnrichment_technical_impact=request.get("vulnrichment_technical_impact"),
    )


def handle_web_request(request_json: str) -> str:
    """Single JSON-in/JSON-out entry point for the browser calculator.

    Request: {"op": "catalog"} or {"op": "calculate", "cvss_vector": ...,
    "aivss_vector": ..., "decision": {...} | null}. Validation errors are
    returned as {"ok": false, "error": message} rather than raised.
    """
    try:
        request = json.loads(request_json)
        op = request.get("op")
        if op == "catalog":
            result: dict[str, Any] = calculator_catalog()
        elif op == "calculate":
            result = {
                "profile": profile_from_vectors(
                    request["cvss_vector"], request["aivss_vector"]
                )
            }
            decision_request = request.get("decision")
            if decision_request is not None:
                try:
                    result["decision"] = _web_decision(
                        {
                            **decision_request,
                            "cvss_vector": request["cvss_vector"],
                            "aivss_vector": request["aivss_vector"],
                        }
                    )
                except (ValueError, TypeError) as exc:
                    result["decision_error"] = str(exc)
        else:
            raise ValueError(f"unknown op {op!r}")
    except (ValueError, KeyError, TypeError) as exc:
        message = f"missing field {exc}" if isinstance(exc, KeyError) else str(exc)
        return json.dumps({"ok": False, "error": message})
    return json.dumps({"ok": True, "result": result})
