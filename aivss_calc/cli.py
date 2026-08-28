"""Command-line interface for the AIVSS 2.0 candidate calculator."""

from __future__ import annotations

import argparse
import json
import sys
from decimal import Decimal, ROUND_HALF_UP
from itertools import product
from pathlib import Path
from typing import Any

from . import __version__
from .ai_metrics import (
    ADJUSTMENT_STATUS,
    AI_METRICS,
    AIProfile,
    AGENTIC_METRIC_ORDER,
    AGENTIC_METRICS,
    ADJUSTMENT_AGENTIC_METRICS,
    CLASSIFYING_AGENTIC_METRICS,
    EFFECT_CLASS_STATUS,
    candidate_adjustment,
    ca_risk_delta,
    ex_risk_delta,
    parse_aivss_vector,
    pt_risk_delta,
    split_ai_vector,
    td_risk_delta,
)
from .assessment import assess, assessment_from_payload, identity_holds
from .cvss_score import round_half_up, score_cvss_bte
from .decision import BOD_2604_TABLE, ExploitationEvidence, decide
from .demo_server import run_demo
from .legacy import score_legacy
from .macrovector import (
    _lookup_table,
    lookup_aivss,
    macrovector,
    parse_cvss_vector,
    promote,
)
from .priority import compute_priority
from .scenarios import SCENARIOS, scenario_payload
from .taxonomy import ASI_TOP_10
from .validation import validate_assessment_input, validate_report
from .versions import RUBRIC_VERSION, WEIGHT_SET_ID

ADJUSTMENT_METRICS = ("EX", "PT", "CA", "TD")
CLASSIFYING_METRICS = ("LC", "CP", "AP", "SR")
ALL_AGENTIC_METRICS = CLASSIFYING_METRICS + ADJUSTMENT_METRICS


def _emit(payload: Any, pretty: bool = True) -> None:
    print(json.dumps(payload, indent=2 if pretty else None, sort_keys=False))


def _parse_optional_bool(value: str) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in ("true", "yes", "1"):
        return True
    if lowered in ("false", "no", "0"):
        return False
    raise argparse.ArgumentTypeError(f"expected true/false, got {value!r}")


def _profile_from_args(args: argparse.Namespace) -> AIProfile | None:
    supplied = {k: getattr(args, k.lower(), None) for k in ALL_AGENTIC_METRICS}
    present = {k for k, value in supplied.items() if value is not None}
    if not present:
        return None
    missing = [name for name in ALL_AGENTIC_METRICS if supplied[name] is None]
    if missing:
        raise ValueError(
            "all eight AIVSS metrics are required when flags are used; "
            f"missing {', '.join(missing)}"
        )
    return AIProfile(**{name.lower(): supplied[name] for name in ALL_AGENTIC_METRICS})


def _resolve_profile(
    args: argparse.Namespace, embedded: AIProfile | None
) -> AIProfile | None:
    flagged = _profile_from_args(args)
    vector_value = getattr(args, "aivss_vector", None)
    vectored = parse_aivss_vector(vector_value) if vector_value else None
    sources = [value for value in (embedded, flagged, vectored) if value is not None]
    if len(sources) > 1:
        raise ValueError(
            "provide the AIVSS profile once, using --aivss-vector, "
            "all eight metric flags, or two-vector display form"
        )
    return sources[0] if sources else None


def _add_ai_metric_flags(p: argparse.ArgumentParser) -> None:
    for name in ALL_AGENTIC_METRICS:
        p.add_argument(
            f"--{name.lower()}",
            choices=sorted(AI_METRICS[name]),
            help=f"Agentic AI metric {name}",
        )


def _evidence_from_args(args: argparse.Namespace) -> ExploitationEvidence:
    return ExploitationEvidence(
        cisa_kev=args.kev,
        vulnrichment_active=args.vulnrichment_active,
        epss=args.epss,
        epss_date=args.epss_date,
        observed_local=args.observed_local,
        poc=args.poc,
    )


def _add_evidence_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--kev", type=_parse_optional_bool)
    p.add_argument("--vulnrichment-active", action="store_true")
    p.add_argument("--epss", type=float)
    p.add_argument("--epss-date")
    p.add_argument("--observed-local", action="store_true")
    p.add_argument("--poc", action="store_true")


def cmd_profile(args: argparse.Namespace) -> int:
    cvss_only, embedded = split_ai_vector(args.vector)
    profile = _resolve_profile(args, embedded)
    if profile is None:
        raise ValueError(
            "profile requires a current-version AIVSS vector or all eight metric flags"
        )
    metrics = parse_cvss_vector(cvss_only)
    mv = macrovector(metrics)
    score = score_cvss_bte(cvss_only)
    adjustment = (
        candidate_adjustment(
            score, ex=profile.ex, pt=profile.pt, ca=profile.ca, td=profile.td
        )
        if profile.complete
        else None
    )
    payload: dict[str, Any] = {
        "mode": "interpretation",
        "status": ADJUSTMENT_STATUS if adjustment else "incomplete",
        "cvss_vector": cvss_only,
        "aivss_vector": profile.to_vector(),
        "macrovector": mv,
        "cvss_bte": score,
        "ex_delta": ex_risk_delta(profile.ex) if adjustment else None,
        "pt_delta": pt_risk_delta(profile.pt) if adjustment else None,
        "ca_delta": ca_risk_delta(profile.ca) if adjustment else None,
        "td_delta": td_risk_delta(profile.td) if adjustment else None,
        "agentic_risk_delta": adjustment.delta if adjustment else None,
        "raw_aivss": adjustment.raw_value if adjustment else None,
        "aivss": adjustment.value if adjustment else None,
        "capped": adjustment.capped if adjustment else None,
        "weight_set": WEIGHT_SET_ID,
        "calibration_status": "not empirically calibrated",
        "note": (
            "Candidate score only. A zero-impact CVSS result remains zero; "
            "LC/CP/AP/SR determine the ordinal Agentic Effect Class."
        ),
        "agentic_ai_profile": profile.describe(),
        "agentic_effect_class": profile.agentic_effect_class(),
        "agentic_effect_class_status": EFFECT_CLASS_STATUS,
    }
    _emit(payload)
    return 0


def cmd_lookup(args: argparse.Namespace) -> int:
    cvss_only, embedded = split_ai_vector(args.vector)
    profile = _resolve_profile(args, embedded)
    if profile is None:
        raise ValueError(
            "lookup requires an Agentic AI metric group in the vector or via flags"
        )
    if not profile.complete:
        raise ValueError("lookup cannot run while any AIVSS metric is X")
    metrics = parse_cvss_vector(cvss_only)
    result = lookup_aivss(cvss_only, metrics, profile.effect_class())
    adjusted = candidate_adjustment(
        result["aivss_btea"],
        ex=profile.ex,
        pt=profile.pt,
        ca=profile.ca,
        td=profile.td,
    )
    macrovector_delta = result.pop("delta")
    result["aivss_btea_before_adjustment"] = result["aivss_btea"]
    result["aivss_btea"] = adjusted.value
    result["raw_aivss_btea"] = adjusted.raw_value
    result["macrovector_delta"] = macrovector_delta
    result["candidate_adjustment_delta"] = adjusted.delta
    result["total_delta"] = round_half_up(adjusted.value - result["cvss_bte"], 1)
    result["capped"] = adjusted.capped
    result["status"] = "experimental-uncalibrated"
    result["generator"] = "S2 equivalence-class promotion"
    _emit(result)
    return 0


def cmd_decide(args: argparse.Namespace) -> int:
    agentic_effect_class = args.agentic_effect_class or "A0"
    td = None
    if args.vector:
        _, embedded = split_ai_vector(args.vector)
        if embedded is not None:
            td = embedded.td
            agentic_effect_class = embedded.agentic_effect_class()
    _emit(
        decide(
            evidence=_evidence_from_args(args),
            publicly_exposed=args.publicly_exposed,
            publicly_exposed_source=args.publicly_exposed_source,
            decision_data_observed_at=args.decision_data_observed_at,
            agentic_effect_class=agentic_effect_class,
            td=td,
            automatable=args.automatable,
            technical_impact=args.technical_impact,
            cve_id=args.cve_id,
            fceb_bod_2604_scope=args.fceb_bod_2604_scope,
            vulnrichment_automatable=args.vulnrichment_automatable,
            vulnrichment_technical_impact=args.vulnrichment_technical_impact,
        )
    )
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    with open(args.input, encoding="utf-8") as handle:
        data = json.load(handle)
    validate_assessment_input(data)

    report = assess(assessment_from_payload(data))
    validate_report(report)
    _emit(report)
    return 0


def cmd_priority(args: argparse.Namespace) -> int:
    _emit(
        compute_priority(
            severity=args.severity,
            business_criticality=args.business_criticality,
            reach=args.reach,
            likelihood=args.likelihood,
        )
    )
    return 0


def cmd_legacy(args: argparse.Namespace) -> int:
    with open(args.factors, encoding="utf-8") as handle:
        data = json.load(handle)
    result = score_legacy(
        cvss_base=data["cvss_base"],
        factors=data["factors"],
        threat_maturity=data.get("threat_maturity", "poc"),
        mitigation_inherent=data.get("mitigation_inherent", "none"),
        mitigation_residual=data.get("mitigation_residual"),
    )
    print(
        "WARNING: historical v0.x reproduction only; not part of AIVSS 2.0 Candidate.",
        file=sys.stderr,
    )
    _emit(result)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    table = _lookup_table()
    regressions = []
    identity_failures = []
    sample_vectors = [
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    ]
    for vector in sample_vectors:
        if not identity_holds(vector):
            identity_failures.append(vector)

    for mv in table:
        for cls in ("A1", "A2"):
            promoted = promote(mv, cls)
            if promoted == mv:
                continue
            if table[promoted] < table[mv]:
                regressions.append((mv, cls))

    rounding_failures = 0
    exact_deltas = {
        "EX": {"W": "0.4", "M": "0.15", "N": "0.0"},
        "PT": {"H": "0.3", "M": "0.1", "L": "0.0"},
        "CA": {"W": "0.3", "M": "0.1", "N": "0.0"},
        "TD": {"H": "0.5", "M": "0.2", "L": "0.0"},
    }
    for tenth in range(101):
        base = Decimal(tenth) / Decimal(10)
        for ex, pt, ca, td in product(
            exact_deltas["EX"],
            exact_deltas["PT"],
            exact_deltas["CA"],
            exact_deltas["TD"],
        ):
            delta = sum(
                (
                    Decimal(exact_deltas["EX"][ex]),
                    Decimal(exact_deltas["PT"][pt]),
                    Decimal(exact_deltas["CA"][ca]),
                    Decimal(exact_deltas["TD"][td]),
                ),
                Decimal("0"),
            )
            raw = Decimal("0") if base == 0 else base + delta
            expected = min(Decimal("10"), raw).quantize(
                Decimal("0.1"), rounding=ROUND_HALF_UP
            )
            actual = candidate_adjustment(float(base), ex=ex, pt=pt, ca=ca, td=td)
            if Decimal(str(actual.value)) != expected:
                rounding_failures += 1

    example_failures: list[str] = []
    source_root = Path(__file__).resolve().parent.parent
    examples_dir = source_root / "examples"
    verify_shipped_files = (source_root / "pyproject.toml").is_file()
    for scenario in SCENARIOS:
        try:
            data = scenario_payload(scenario["risk_category"])
            validate_assessment_input(data)
            report = assess(assessment_from_payload(data))
            validate_report(report)
            path = examples_dir / f"{scenario['risk_category'].lower()}-example.json"
            if verify_shipped_files and not path.is_file():
                raise ValueError("shipped example is missing")
            if verify_shipped_files:
                with path.open(encoding="utf-8") as handle:
                    shipped = json.load(handle)
                if shipped != data:
                    raise ValueError("shipped example differs from canonical scenario")
        except Exception as exc:
            example_failures.append(f"{scenario['risk_category']}: {exc}")

    expected_bod_keys = {
        (kev, exposed, automatable, impact)
        for kev, exposed, automatable, impact in product(
            (False, True), (False, True), (False, True), ("partial", "total")
        )
    }
    bod_table_complete = set(BOD_2604_TABLE) == expected_bod_keys
    passed = (
        not identity_failures
        and not regressions
        and not rounding_failures
        and not example_failures
        and bod_table_complete
    )
    _emit(
        {
            "passed": passed,
            "macrovectors": len(table),
            "identity_rule_sample_failures": identity_failures,
            "identity_rule_sample_passed": not identity_failures,
            "macrovector_promotion_violations": len(regressions),
            "exact_rounding_combinations": 101 * 3**4,
            "exact_rounding_failures": rounding_failures,
            "bod_2604_table_rows": len(BOD_2604_TABLE),
            "bod_2604_table_complete": bod_table_complete,
            "validated_scenarios": len(SCENARIOS) - len(example_failures),
            "scenario_failures": example_failures,
            "saturated_no_op": {
                "A1": sum(1 for mv in table if promote(mv, "A1") == mv),
                "A2": sum(1 for mv in table if promote(mv, "A2") == mv),
            },
        }
    )
    return 0 if passed else 1


def cmd_taxonomy(args: argparse.Namespace) -> int:
    _emit({"OWASP Top 10 for Agentic Applications 2026": ASI_TOP_10})
    return 0


def cmd_rubric(args: argparse.Namespace) -> int:
    """Emit the exhaustive value sets for all eight Agentic AI metrics."""
    metrics: dict[str, dict[str, dict[str, str]]] = {}
    for name in AGENTIC_METRIC_ORDER:
        metrics[name] = {
            code: {"label": label, "summary": definition}
            for code, (label, definition) in AGENTIC_METRICS[name].items()
        }
    _emit(
        {
            "rubric_version": RUBRIC_VERSION,
            "reference": "docs/METRIC-RUBRIC.md",
            "classifying_metrics": list(CLASSIFYING_AGENTIC_METRICS),
            "adjustment_metrics": list(ADJUSTMENT_AGENTIC_METRICS),
            "metrics": metrics,
        }
    )
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    run_demo(host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aivss-calc")
    parser.add_argument(
        "--version", action="version", version=f"aivss-calc {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("profile")
    p.add_argument("vector")
    p.add_argument("--aivss-vector")
    _add_ai_metric_flags(p)
    p.set_defaults(func=cmd_profile)

    p = sub.add_parser("lookup")
    p.add_argument("vector")
    p.add_argument("--aivss-vector")
    _add_ai_metric_flags(p)
    p.set_defaults(func=cmd_lookup)

    p = sub.add_parser("decide")
    p.add_argument("--vector")
    p.add_argument(
        "--agentic-effect-class",
        choices=("A0", "A1", "A2", "AX"),
        dest="agentic_effect_class",
    )
    p.add_argument("--publicly-exposed", type=_parse_optional_bool)
    p.add_argument("--publicly-exposed-source")
    p.add_argument("--decision-data-observed-at")
    p.add_argument("--cve-id")
    p.add_argument("--fceb-bod-2604-scope", action="store_true")
    p.add_argument("--automatable", type=_parse_optional_bool)
    p.add_argument("--technical-impact", choices=("partial", "total"))
    p.add_argument("--vulnrichment-automatable", type=_parse_optional_bool)
    p.add_argument("--vulnrichment-technical-impact", choices=("partial", "total"))
    _add_evidence_flags(p)
    p.set_defaults(func=cmd_decide)

    p = sub.add_parser("assess")
    p.add_argument("input")
    p.set_defaults(func=cmd_assess)

    p = sub.add_parser("priority")
    p.add_argument("--severity", type=float, required=True)
    p.add_argument(
        "--business-criticality", choices=("high", "medium", "low"), default="medium"
    )
    p.add_argument("--reach", choices=("high", "medium", "low"), default="medium")
    p.add_argument("--likelihood", type=float, default=0.5)
    p.set_defaults(func=cmd_priority)

    p = sub.add_parser("legacy")
    p.add_argument("--factors", required=True)
    p.set_defaults(func=cmd_legacy)

    p = sub.add_parser("verify")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("taxonomy")
    p.set_defaults(func=cmd_taxonomy)

    p = sub.add_parser(
        "rubric", help="List all eight Agentic AI metric value sets and definitions"
    )
    p.set_defaults(func=cmd_rubric)

    p = sub.add_parser(
        "demo",
        help="Launch the OWASP ASI Top 10 AIVSS demo dashboard (http server)",
    )
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, KeyError, FileNotFoundError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
