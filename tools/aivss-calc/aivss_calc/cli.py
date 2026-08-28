"""Command-line interface for the AIVSS v1.0 reference calculator."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import __version__
from .ai_metrics import AI_METRICS, AIProfile, split_ai_vector
from .assessment import Assessment, OrgContext, Provenance, assess, identity_holds
from .cvss_score import score_cvss_bte
from .decision import ExploitationEvidence, decide
from .legacy import score_legacy
from .macrovector import _lookup_table, lookup_aivss, macrovector, parse_cvss_vector, promote
from .priority import compute_priority
from .taxonomy import ASI_TOP_10


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
    raise argparse.ArgumentTypeError(
        f"expected true/false, got {value!r}"
    )


def _profile_from_args(args: argparse.Namespace) -> AIProfile | None:
    supplied = {k: getattr(args, k.lower(), None) for k in ("LC", "CP", "AP", "SR", "TD")}
    scored = {k: v for k, v in supplied.items() if k != "TD" and v is not None}
    if not scored and supplied["TD"] is None:
        return None
    if scored and len(scored) != 4:
        missing = [k for k in ("LC", "CP", "AP", "SR") if supplied[k] is None]
        raise SystemExit(
            f"error: all four scored AI metrics are required; missing {', '.join(missing)}"
        )
    if scored and supplied["TD"] is None:
        raise SystemExit("error: TD is mandatory when scored AI metrics are supplied")
    if not scored:
        return AIProfile(td=supplied["TD"], scored_present=False)
    return AIProfile(
        lc=supplied["LC"], cp=supplied["CP"], ap=supplied["AP"], sr=supplied["SR"], td=supplied["TD"]
    )


def _add_ai_metric_flags(p: argparse.ArgumentParser) -> None:
    for name in ("LC", "CP", "AP", "SR", "TD"):
        p.add_argument(
            f"--{name.lower()}",
            choices=sorted(AI_METRICS[name]),
            help=f"AI metric {name}",
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
    p.add_argument("--kev", action="store_true")
    p.add_argument("--vulnrichment-active", action="store_true")
    p.add_argument("--epss", type=float)
    p.add_argument("--epss-date")
    p.add_argument("--observed-local", action="store_true")
    p.add_argument("--poc", action="store_true")


def cmd_profile(args: argparse.Namespace) -> int:
    cvss_only, embedded = split_ai_vector(args.vector)
    profile = _profile_from_args(args) if any(
        getattr(args, k.lower(), None) is not None for k in ("LC", "CP", "AP", "SR", "TD")
    ) else embedded
    metrics = parse_cvss_vector(cvss_only)
    mv = macrovector(metrics)
    score = score_cvss_bte(cvss_only)
    payload: dict[str, Any] = {
        "mode": "interpretation",
        "status": "normative",
        "vector": cvss_only if profile is None else f"{cvss_only}/{profile.to_vector_fragment()}",
        "macrovector": mv,
        "aivss": score,
        "note": "AI metrics do not modify the numeric score in interpretation mode.",
    }
    if profile is not None:
        payload["ai_profile"] = profile.describe()
        payload["ai_effect_class"] = profile.effect_class()
    else:
        payload["ai_effect_class"] = "A0"
    _emit(payload)
    return 0


def cmd_lookup(args: argparse.Namespace) -> int:
    cvss_only, embedded = split_ai_vector(args.vector)
    profile = _profile_from_args(args) if any(
        getattr(args, k.lower(), None) is not None for k in ("LC", "CP", "AP", "SR", "TD")
    ) else embedded
    if profile is None:
        raise SystemExit("error: lookup requires an AI metric group in the vector or via flags")
    metrics = parse_cvss_vector(cvss_only)
    result = lookup_aivss(cvss_only, metrics, profile.effect_class())
    result["status"] = "provisional -- strawman lookup, pending expert calibration"
    result["generator"] = "S2 equivalence-class promotion"
    _emit(result)
    return 0


def cmd_decide(args: argparse.Namespace) -> int:
    ai_class = args.ai_class or "A0"
    sr = None
    cvss_metrics = None
    if args.vector:
        cvss_only, embedded = split_ai_vector(args.vector)
        cvss_metrics = parse_cvss_vector(cvss_only)
        if embedded is not None and embedded.scored_present:
            ai_class = embedded.effect_class()
            sr = embedded.sr
    _emit(
        decide(
            evidence=_evidence_from_args(args),
            publicly_exposed=args.publicly_exposed,
            ai_class=ai_class,
            automatable=args.automatable,
            technical_impact=args.technical_impact,
            sr=sr,
            cvss_metrics=cvss_metrics,
            cve_id=args.cve_id,
            vulnrichment_automatable=args.vulnrichment_automatable,
            vulnrichment_technical_impact=args.vulnrichment_technical_impact,
        )
    )
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    with open(args.input, encoding="utf-8") as handle:
        data = json.load(handle)

    ai = data.get("ai_profile")
    profile = AIProfile(**{k.lower(): v for k, v in ai.items()}) if ai else None
    org = data.get("org_context")

    report = assess(
        Assessment(
            finding_id=data["finding_id"],
            cvss_vector=data["cvss_vector"],
            asi_category=data["risk_category"],
            ai_profile=profile,
            evidence=ExploitationEvidence(**data.get("evidence", {})),
            org_context=OrgContext(**org) if org else None,
            provenance=Provenance(**data.get("provenance", {})),
            publicly_exposed=data.get("publicly_exposed"),
            cve_id=data.get("cve_id"),
            automatable=data.get("automatable"),
            technical_impact=data.get("technical_impact"),
            vulnrichment_automatable=data.get("vulnrichment_automatable"),
            vulnrichment_technical_impact=data.get("vulnrichment_technical_impact"),
            include_decision=data.get("include_decision", True),
            include_priority=data.get("include_priority", org is not None),
        )
    )
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
    print("WARNING: uplift model is INFORMATIVE ONLY and deprecated at v1.0.", file=sys.stderr)
    _emit(result)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    table = _lookup_table()
    failures = []
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

    _emit(
        {
            "macrovectors": len(table),
            "identity_rule_sample_failures": identity_failures,
            "identity_rule_holds": not identity_failures,
            "monotonicity_violations": len(regressions),
            "saturated_no_op": {
                "A1": sum(1 for mv in table if promote(mv, "A1") == mv),
                "A2": sum(1 for mv in table if promote(mv, "A2") == mv),
            },
        }
    )
    return 0 if not identity_failures and not regressions else 1


def cmd_taxonomy(args: argparse.Namespace) -> int:
    _emit({"OWASP Top 10 for Agentic Applications 2026": ASI_TOP_10})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aivss-calc")
    parser.add_argument("--version", action="version", version=f"aivss-calc {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("profile")
    p.add_argument("vector")
    _add_ai_metric_flags(p)
    p.set_defaults(func=cmd_profile)

    p = sub.add_parser("lookup")
    p.add_argument("vector")
    _add_ai_metric_flags(p)
    p.set_defaults(func=cmd_lookup)

    p = sub.add_parser("decide")
    p.add_argument("--vector")
    p.add_argument("--ai-class", choices=("A0", "A1", "A2"))
    p.add_argument("--publicly-exposed", action="store_true")
    p.add_argument("--cve-id")
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
    p.add_argument("--business-criticality", choices=("high", "medium", "low"), default="medium")
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
