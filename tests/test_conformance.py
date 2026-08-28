"""Cross-artifact, schema, CLI, and negative conformance tests."""

from __future__ import annotations

import copy
import json
import pathlib
import tomllib
from itertools import product

import pytest

from aivss_calc import Assessment, Provenance, assess, assessment_from_payload
from aivss_calc.ai_metrics import (
    AIVSS_EXTENSION_PREFIX,
    AGENTIC_METRIC_ORDER,
    AGENTIC_METRICS,
    AIProfile,
    candidate_adjustment,
    parse_aivss_vector,
)
from aivss_calc.cli import main
from aivss_calc.scenarios import SCENARIOS, scenario_payload
from aivss_calc.validation import validate_assessment_input, validate_report
from aivss_calc.versions import (
    CALCULATOR_VERSION,
    EXTENSION_VECTOR_VERSION,
    REPORT_SCHEMA_VERSION,
    RUBRIC_VERSION,
    SPEC_VERSION,
    WEIGHT_SET_ID,
)

REPO = pathlib.Path(__file__).resolve().parents[1]
CVSS = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P"
EVIDENCE = scenario_payload("ASI06")["metric_evidence"]


def test_versions_are_consistent_across_package_and_schemas():
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    report_schema = json.loads(
        (REPO / "schemas" / "aivss-report-v1.0.json").read_text(encoding="utf-8")
    )
    manifest = json.loads((REPO / "aivss-extension.json").read_text(encoding="utf-8"))
    assert project["project"]["version"] == CALCULATOR_VERSION
    assert (
        report_schema["properties"]["calculator_version"]["const"] == CALCULATOR_VERSION
    )
    assert report_schema["properties"]["rubric_version"]["const"] == RUBRIC_VERSION
    assert report_schema["properties"]["aivss_version"]["const"] == SPEC_VERSION
    assert (
        report_schema["properties"]["report_schema_version"]["const"]
        == REPORT_SCHEMA_VERSION
    )
    assert (
        report_schema["$defs"]["candidateScore"]["properties"]["weight_set"]["const"]
        == WEIGHT_SET_ID
    )
    assert manifest["version"] == EXTENSION_VECTOR_VERSION
    assert manifest["vector_prefix"] == AIVSS_EXTENSION_PREFIX
    assert manifest["metric_order"] == list(AGENTIC_METRIC_ORDER)


def test_every_shipped_example_is_current_and_valid():
    files = sorted((REPO / "examples").glob("asi??-example.json"))
    assert len(files) == len(SCENARIOS) == 10
    for path in files:
        payload = json.loads(path.read_text(encoding="utf-8"))
        validate_assessment_input(payload)
        report = assess(assessment_from_payload(payload))
        validate_report(report)
        expected = scenario_payload(payload["risk_category"])
        assert payload == expected


def test_all_metric_combinations_have_deterministic_completeness_and_class():
    names = list(AGENTIC_METRIC_ORDER)
    for values in product(*(AGENTIC_METRICS[name] for name in names)):
        profile = AIProfile(**dict(zip((name.lower() for name in names), values)))
        assert profile.complete == ("X" not in values)
        assert profile.effect_class() in ("A0", "A1", "A2", "AX")
        if any(
            getattr(profile, name.lower()) == "X" for name in ("LC", "CP", "AP", "SR")
        ):
            assert profile.effect_class() == "AX"


def test_unknown_value_withholds_candidate_score():
    vector = "AIVSS:1.0/LC:X/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H"
    report = assess(
        Assessment(
            finding_id="unknown",
            path_id="unknown-path",
            cvss_vector=CVSS,
            aivss_vector=vector,
            asi_category="ASI06",
            agentic_applicability=copy.deepcopy(
                scenario_payload("ASI06")["agentic_applicability"]
            ),
            metric_evidence=copy.deepcopy(EVIDENCE),
            publicly_exposed=True,
            automatable=True,
            technical_impact="total",
            include_decision=False,
            provenance=Provenance(assessed_at="2026-08-27T00:00:00Z"),
        )
    )
    candidate = report["scores"]["candidate_adjusted"]
    assert candidate["status"] == "incomplete"
    assert candidate["aivss"] is None
    assert candidate["zero_impact_invariant_applied"] is None
    assert report["agentic_ai_profile"]["agentic_effect_class"] == "AX"
    assert (
        report["agentic_ai_profile"]["agentic_effect_class_status"]
        == "candidate-unvalidated"
    )
    validate_report(report)


def test_zero_impact_and_cap_are_explicit():
    zero = candidate_adjustment(0.0, ex="W", pt="H", ca="W", td="H")
    capped = candidate_adjustment(9.8, ex="W", pt="H", ca="W", td="H")
    assert zero.value == zero.raw_value == 0.0
    assert zero.capped is False
    assert capped.raw_value == 11.3
    assert capped.value == 10.0
    assert capped.capped is True


def test_semantic_validator_rejects_tampered_score():
    report = assess(assessment_from_payload(scenario_payload("ASI01")))
    tampered = copy.deepcopy(report)
    tampered["scores"]["candidate_adjusted"]["aivss"] = 1.0
    with pytest.raises(ValueError, match="aivss does not match"):
        validate_report(tampered)


def test_input_schema_rejects_missing_evidence_and_extra_fields():
    payload = scenario_payload("ASI01")
    del payload["metric_evidence"]["TD"]
    payload["invented"] = True
    with pytest.raises(Exception):
        validate_assessment_input(payload)


def test_input_without_decision_omits_decision_only_inputs():
    payload = scenario_payload("ASI01")
    payload["include_decision"] = False
    for name in (
        "publicly_exposed",
        "publicly_exposed_source",
        "decision_data_observed_at",
        "automatable",
        "technical_impact",
    ):
        del payload[name]
    validate_assessment_input(payload)


def test_input_semantics_reject_whitespace_only_evidence():
    payload = scenario_payload("ASI01")
    payload["metric_evidence"]["TD"]["rationale"] = "  "
    with pytest.raises(ValueError, match="rationale"):
        validate_assessment_input(payload)


def test_report_validator_rejects_fields_from_another_decision_branch():
    report = assess(assessment_from_payload(scenario_payload("ASI01")))
    report["decision"]["bod_2604_timeline"] = report["decision"][
        "bod_2604_analogy_timeline"
    ]
    report["decision"]["bod_2604_label"] = report["decision"]["bod_2604_analogy_label"]
    with pytest.raises(Exception):
        validate_report(report)


def test_cli_rejects_partial_agentic_flags(capsys):
    assert main(["profile", CVSS, "--ex", "W"]) == 2
    assert "all eight AIVSS metrics are required" in capsys.readouterr().err


def test_cli_accepts_separate_extension_vector(capsys):
    vector = "AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H"
    assert main(["profile", CVSS, "--aivss-vector", vector]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["cvss_vector"] == CVSS
    assert output["aivss_vector"] == vector
    assert output["status"] == "experimental-uncalibrated"


def test_lookup_output_separates_macrovector_and_adjustment_deltas(capsys):
    vector = "AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H"
    assert main(["lookup", CVSS, "--aivss-vector", vector]) == 0
    output = json.loads(capsys.readouterr().out)
    assert "delta" not in output
    assert output["total_delta"] == pytest.approx(
        output["aivss_btea"] - output["cvss_bte"], abs=0.05
    )
    assert output["candidate_adjustment_delta"] == 1.3


def test_extension_parser_rejects_out_of_order_metrics():
    with pytest.raises(ValueError, match="out of order"):
        parse_aivss_vector("AIVSS:1.0/CP:C/LC:D/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H")
