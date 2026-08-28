"""Conformance and regression tests for the AIVSS 1.0 calculator.

Assertions are exact. A scoring standard whose own tests carry wide tolerances
cannot arbitrate between two implementations that disagree.
"""

from __future__ import annotations

import json
import pathlib
from decimal import Decimal, ROUND_HALF_UP
from itertools import product

import pytest

from aivss_calc import (
    BOD_2604_TABLE,
    AIProfile,
    Assessment,
    ExploitationEvidence,
    OrgContext,
    Provenance,
    assess,
    assessment_from_payload,
    bod_timeline,
    compute_priority,
    lookup_aivss,
    macrovector,
    macrovector_score,
    normalize_asi,
    parse_aivss_vector,
    parse_cvss_vector,
    promote,
    split_ai_vector,
)
from aivss_calc.ai_metrics import (
    AGENTIC_METRIC_ORDER,
    AGENTIC_METRICS,
    ADJUSTMENT_AGENTIC_METRICS,
    CLASSIFYING_AGENTIC_METRICS,
    agentic_risk_delta,
    apply_agentic_risk,
    candidate_adjustment,
    ca_risk_delta,
    classify_sr,
    ex_risk_delta,
    pt_risk_delta,
    td_risk_delta,
)
from aivss_calc.decision import TIMELINE_URGENCY, advance_timeline, decide, escalate
from aivss_calc.legacy import compute_severity, factor_mean, score_legacy
from aivss_calc.cvss_score import round_half_up, score_cvss_bte
from aivss_calc.macrovector import _lookup_table
from aivss_calc.taxonomy import ASI_TOP_10, V08_CATEGORY_CROSSWALK
from aivss_calc.validation import validate_assessment_input, validate_report

REPO = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = REPO / "schemas" / "aivss-report-v1.0.json"

# CVSS-BTE 7.8 (interpolated), MacroVector ceiling 8.0.
EXAMPLE_VECTOR = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P"
EXAMPLE_CVSS_BTE = 7.8
EXAMPLE_EX_DELTA = 0.4
EXAMPLE_PT_DELTA = 0.3
EXAMPLE_CA_DELTA = 0.1
EXAMPLE_TD_DELTA = 0.5
EXAMPLE_AGENTIC_RISK_DELTA = 1.3
EXAMPLE_AIVSS = 9.1
EXAMPLE_AI = "AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H"
EXAMPLE_FULL = f"{EXAMPLE_VECTOR} {EXAMPLE_AI}"
DECISION_CONTEXT = {
    "publicly_exposed_source": "test fixture",
    "decision_data_observed_at": "2026-08-27T00:00:00Z",
}
APPLICABILITY = {
    "model_directed_goal_pursuit": True,
    "action_selection_or_sequencing": True,
    "rationale": "Test fixture exercises an agentic path.",
    "evidence_refs": ["test://agentic-applicability"],
}


def metric_evidence(vector: str) -> dict[str, dict]:
    assessed = parse_aivss_vector(vector)
    result = {
        name: {
            "rationale": f"Test evidence for {name}",
            "evidence_refs": [f"test://{name.lower()}"],
        }
        for name in AGENTIC_METRIC_ORDER
    }
    successes = {"R": 30, "P": 18, "U": 0}.get(assessed.sr)
    if successes is None:
        result["SR"]["method"] = "insufficient-evidence"
    else:
        classified = classify_sr(
            successes=successes,
            episodes=30,
            production_equivalent=True,
            budget_enforced=True,
            independent=True,
        )
        result["SR"].update(
            {
                "method": "empirical",
                "successes": successes,
                "episodes": 30,
                "retry_budget": 3,
                "production_equivalent": True,
                "budget_enforced": True,
                "independent": True,
                "lower_bound": classified.lower_bound,
                "upper_bound": classified.upper_bound,
            }
        )
    ca = {
        "W": (False, False, False, False),
        "M": (True, False, True, False),
        "N": (True, True, True, False),
        "X": (None, None, None, None),
    }[assessed.ca]
    result["CA"].update(
        dict(
            zip(
                (
                    "ceiling_defined",
                    "coverage_complete",
                    "fail_closed",
                    "bypass_demonstrated",
                ),
                ca,
                strict=True,
            )
        )
    )
    td = {
        "H": (True, False, False, False, False, False),
        "M": (True, True, True, False, False, False),
        "L": (True, True, True, True, True, True),
        "X": (False, None, None, None, None, None),
    }[assessed.td]
    result["TD"].update(
        dict(
            zip(
                (
                    "retrieval_tested",
                    "ordered_actions_reconstructable",
                    "affected_principals_bounded",
                    "required_fields_complete",
                    "integrity_protected",
                    "retention_verified",
                ),
                td,
                strict=True,
            )
        )
    )
    return result


METRIC_EVIDENCE = metric_evidence(EXAMPLE_AI)


def profile(**overrides: str) -> AIProfile:
    values = {
        "lc": "N",
        "cp": "N",
        "ap": "N",
        "sr": "U",
        "ex": "N",
        "pt": "L",
        "ca": "N",
        "td": "L",
    }
    values.update(overrides)
    return AIProfile(**values)


class TestMacroVectorTable:
    def test_has_270_equivalence_classes(self):
        assert len(_lookup_table()) == 270

    def test_joint_eq3_eq6_constraint(self):
        assert not [k for k in _lookup_table() if k[2] == "2" and k[5] == "0"]

    def test_scores_within_range(self):
        assert all(0.0 <= v <= 10.0 for v in _lookup_table().values())


class TestIdentityRule:
    """The experimental MacroVector mapping preserves A0 identity."""

    def test_identity_holds_for_every_macrovector(self):
        table = _lookup_table()
        for mv, score in table.items():
            assert promote(mv, "A0") == mv
            assert macrovector_score(promote(mv, "A0")) == score

    def test_absent_ai_metrics_yield_a0(self):
        metrics = parse_cvss_vector(EXAMPLE_VECTOR)
        result = lookup_aivss(EXAMPLE_VECTOR, metrics, "A0")
        assert result["agentic_effect_class"] == "A0"
        assert result["aivss_btea"] == EXAMPLE_CVSS_BTE
        assert result["delta"] == 0.0

    def test_agentic_risk_delta_adjusts_score(self):
        """EX, PT, CA, and TD feed the transparent candidate adjustment."""
        metrics = parse_cvss_vector(EXAMPLE_VECTOR)
        base = lookup_aivss(EXAMPLE_VECTOR, metrics, "A0")["aivss_btea"]
        cases = (
            ("W", "H", "W", "H", 1.5),
            ("M", "M", "M", "M", 0.55),
            ("N", "L", "N", "L", 0.0),
        )
        for ex, pt, ca, td, total in cases:
            ai = profile(ex=ex, pt=pt, ca=ca, td=td)
            assert ai.effect_class() == "A0"
            assert agentic_risk_delta(ex=ex, pt=pt, ca=ca, td=td) == total
            assert apply_agentic_risk(
                base, ex=ex, pt=pt, ca=ca, td=td
            ) == round_half_up(min(10.0, base + total), 1)

    def test_adjustment_rounding_is_exact_for_every_score_and_factor_combination(self):
        tables = [
            ("W", "M", "N"),
            ("H", "M", "L"),
            ("W", "M", "N"),
            ("H", "M", "L"),
        ]
        for tenth in range(101):
            base = Decimal(tenth) / Decimal(10)
            for ex, pt, ca, td in product(*tables):
                expected_delta = sum(
                    (
                        Decimal(str(ex_risk_delta(ex))),
                        Decimal(str(pt_risk_delta(pt))),
                        Decimal(str(ca_risk_delta(ca))),
                        Decimal(str(td_risk_delta(td))),
                    ),
                    Decimal("0"),
                )
                raw = Decimal("0") if base == 0 else base + expected_delta
                expected = min(Decimal("10"), raw).quantize(
                    Decimal("0.1"), rounding=ROUND_HALF_UP
                )
                actual = candidate_adjustment(float(base), ex=ex, pt=pt, ca=ca, td=td)
                assert Decimal(str(actual.value)) == expected
                assert Decimal(str(actual.raw_value)) == raw

    def test_candidate_score_rejects_non_numeric_input(self):
        with pytest.raises(ValueError, match="finite decimal"):
            candidate_adjustment("7.8", ex="N", pt="L", ca="N", td="L")

    def test_interpolated_score_differs_from_macrovector_ceiling(self):
        metrics = parse_cvss_vector(EXAMPLE_VECTOR)
        assert score_cvss_bte(EXAMPLE_VECTOR) == EXAMPLE_CVSS_BTE
        assert macrovector_score(macrovector(metrics)) == 8.0


class TestPromotion:
    def test_promotion_never_lowers_the_score(self):
        table = _lookup_table()
        for mv, score in table.items():
            for cls in ("A0", "A1", "A2"):
                assert macrovector_score(promote(mv, cls)) >= score

    def test_promoted_macrovector_always_exists(self):
        table = _lookup_table()
        for mv in table:
            for cls in ("A0", "A1", "A2"):
                assert promote(mv, cls) in table

    def test_a2_is_at_least_a1(self):
        table = _lookup_table()
        for mv in table:
            assert macrovector_score(promote(mv, "A2")) >= macrovector_score(
                promote(mv, "A1")
            )

    def test_promotion_is_bounded_by_ten(self):
        assert all(
            macrovector_score(promote(mv, "A2")) <= 10.0 for mv in _lookup_table()
        )

    def test_unknown_class_rejected(self):
        with pytest.raises(ValueError, match="Unknown Agentic Effect Class"):
            promote("000000", "A3")


class TestAIEffectClass:
    def test_direct_cross_session_case(self):
        """Direct control plus cross-session persistence classifies as A2."""
        assert profile(lc="D", cp="C").effect_class() == "A2"

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"ap": "L"},
            {"lc": "D", "cp": "C"},
            {"lc": "I", "cp": "C"},
            {"lc": "D", "sr": "R"},
        ],
    )
    def test_a2_conditions(self, kwargs):
        assert profile(**kwargs).effect_class() == "A2"

    def test_adjustment_metrics_do_not_promote_effect_class(self):
        assert profile(lc="I", ex="W").effect_class() == "A1"
        assert profile(pt="H", ex="M").effect_class() == "A0"
        assert profile(sr="R", ca="W").effect_class() == "A1"

    @pytest.mark.parametrize(
        "kwargs",
        [{"lc": "I"}, {"cp": "S"}, {"ap": "C"}, {"sr": "R"}, {"lc": "M"}],
    )
    def test_a1_conditions(self, kwargs):
        assert profile(**kwargs).effect_class() == "A1"

    def test_a0_only_when_all_benign(self):
        assert profile().effect_class() == "A0"

    def test_every_combination_yields_a_valid_class(self):
        for lc in "DIMN":
            for cp in "CSN":
                for ap in "LCN":
                    for sr in "RPU":
                        cls = profile(lc=lc, cp=cp, ap=ap, sr=sr).effect_class()
                        assert cls in ("A0", "A1", "A2")

    def test_class_is_monotone_in_each_metric(self):
        """Worsening any single metric must never lower the effect class."""
        order = {"A0": 0, "A1": 1, "A2": 2}
        scales = {"lc": "NMID", "cp": "NSC", "ap": "NCL", "sr": "UPR"}
        for name, scale in scales.items():
            for lc in "DIMN":
                for cp in "CSN":
                    for ap in "LCN":
                        for sr in "RPU":
                            base = {"lc": lc, "cp": cp, "ap": ap, "sr": sr}
                            for i in range(len(scale) - 1):
                                lo = dict(base, **{name: scale[i]})
                                hi = dict(base, **{name: scale[i + 1]})
                                assert (
                                    order[profile(**hi).effect_class()]
                                    >= order[profile(**lo).effect_class()]
                                )

    def test_illegal_value_rejected(self):
        with pytest.raises(ValueError, match="Illegal value"):
            profile(lc="Z")

    def test_unknown_classifying_metric_yields_ax(self):
        assert profile(lc="X").effect_class() == "AX"
        assert profile(lc="X").complete is False


class TestSRClassification:
    def test_empirical_thresholds_are_reproducible(self):
        controls = {
            "production_equivalent": True,
            "budget_enforced": True,
            "independent": True,
        }
        reliable = classify_sr(successes=30, episodes=30, **controls)
        probabilistic = classify_sr(successes=18, episodes=30, **controls)
        unreliable = classify_sr(successes=0, episodes=30, **controls)
        assert reliable.value == "R"
        assert reliable.lower_bound == pytest.approx(0.917, abs=0.001)
        assert probabilistic.value == "P"
        assert unreliable.value == "U"
        assert unreliable.upper_bound == pytest.approx(0.083, abs=0.001)

    def test_insufficient_controls_or_sample_yield_unknown(self):
        assert classify_sr(successes=29, episodes=29).value == "X"
        assert (
            classify_sr(
                successes=30,
                episodes=30,
                production_equivalent=True,
                budget_enforced=True,
                independent=False,
            ).value
            == "X"
        )

    def test_deterministic_proof_overrides_empirical_inputs(self):
        assert classify_sr(deterministic_outcome="success").value == "R"
        assert classify_sr(deterministic_outcome="failure").value == "U"


class TestMetricPartitions:
    """Eight metrics with closed value sets — every code must be assignable."""

    EXPECTED_COUNTS = {
        "LC": 5,
        "CP": 4,
        "AP": 4,
        "SR": 4,
        "EX": 4,
        "PT": 4,
        "CA": 4,
        "TD": 4,
    }

    def test_eight_metrics_in_fixed_order(self):
        assert AGENTIC_METRIC_ORDER == ("LC", "CP", "AP", "SR", "EX", "PT", "CA", "TD")

    def test_classifying_and_adjustment_partition_the_eight(self):
        assert set(CLASSIFYING_AGENTIC_METRICS) | set(
            ADJUSTMENT_AGENTIC_METRICS
        ) == set(AGENTIC_METRIC_ORDER)
        assert set(CLASSIFYING_AGENTIC_METRICS).isdisjoint(ADJUSTMENT_AGENTIC_METRICS)

    @pytest.mark.parametrize("name,count", list(EXPECTED_COUNTS.items()))
    def test_value_set_size(self, name, count):
        assert len(AGENTIC_METRICS[name]) == count

    def test_every_adjustment_value_parses_in_profile(self):
        for ex in AGENTIC_METRICS["EX"]:
            for pt in AGENTIC_METRICS["PT"]:
                for ca in AGENTIC_METRICS["CA"]:
                    for td in AGENTIC_METRICS["TD"]:
                        ai = profile(ex=ex, pt=pt, ca=ca, td=td)
                        assert ai.complete == ("X" not in (ex, pt, ca, td))


class TestVectorParsing:
    def test_round_trip(self):
        cvss, parsed = split_ai_vector(EXAMPLE_FULL)
        assert cvss == EXAMPLE_VECTOR
        assert parsed is not None
        assert parsed.to_vector() == EXAMPLE_AI

    def test_no_ai_group_returns_none(self):
        cvss, parsed = split_ai_vector(EXAMPLE_VECTOR)
        assert cvss == EXAMPLE_VECTOR
        assert parsed is None

    def test_partial_ai_group_rejected(self):
        with pytest.raises(ValueError, match="all eight"):
            parse_aivss_vector("AIVSS:1.0/LC:D/CP:C")

    def test_appended_ai_metrics_are_rejected(self):
        with pytest.raises(ValueError, match="separate"):
            split_ai_vector(f"{EXAMPLE_VECTOR}/LC:D/CP:C/AP:L/SR:R")

    def test_duplicate_ai_metric_rejected(self):
        with pytest.raises(ValueError, match="Duplicate AIVSS metric"):
            parse_aivss_vector("AIVSS:1.0/LC:D/LC:I/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H")

    def test_wrong_extension_version_rejected(self):
        with pytest.raises(ValueError, match="must begin"):
            parse_aivss_vector(EXAMPLE_AI.replace("AIVSS:1.0", "AIVSS:2.0"))

    @pytest.mark.parametrize(
        "vector,match",
        [
            ("CVSS:3.1/AV:N", "must begin with"),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/ZZ:Q",
                "Unknown",
            ),
            (
                "CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "Illegal value",
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",
                "Missing mandatory",
            ),
            (
                "CVSS:4.0/AV:N/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "Duplicate",
            ),
            (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA",
                "Malformed",
            ),
            (
                "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "order",
            ),
        ],
    )
    def test_malformed_vectors_rejected(self, vector, match):
        with pytest.raises(ValueError, match=match):
            parse_cvss_vector(vector)

    def test_modified_metrics_override_base(self):
        base = "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        assert macrovector(parse_cvss_vector(base))[0] == "2"
        assert macrovector(parse_cvss_vector(base + "/MAV:N"))[0] == "0"

    def test_exploit_maturity_defaults_to_worst_case(self):
        base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        assert macrovector(parse_cvss_vector(base))[4] == "0"
        assert macrovector(parse_cvss_vector(base + "/E:U"))[4] == "2"


class TestBOD2604:
    def test_all_sixteen_official_rows_match(self):
        expected = {
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
        assert BOD_2604_TABLE == expected

    def test_kev_plus_total_without_exposure_or_automation_is_14_days(self):
        """Regression: the fast tier needs exposure or automatability, not just
        KEV plus total impact. Hand-written boolean logic gets this wrong."""
        assert (
            bod_timeline(
                in_kev=True,
                publicly_exposed=False,
                automatable=False,
                technical_impact="total",
            )
            == "14D"
        )

    @pytest.mark.parametrize(
        "args,expected",
        [
            ((False, False, False, "partial"), "FSU"),
            ((False, False, False, "total"), "FSU"),
            ((True, True, True, "total"), "3DF"),
            ((True, True, False, "total"), "3DF"),
            ((True, False, True, "total"), "3DF"),
            ((False, True, True, "total"), "3D"),
            ((True, True, True, "partial"), "3D"),
            ((False, False, True, "total"), "60D"),
            ((False, True, False, "partial"), "60D"),
        ],
    )
    def test_table_rows(self, args, expected):
        kev, exposed, auto, impact = args
        assert (
            bod_timeline(
                in_kev=kev,
                publicly_exposed=exposed,
                automatable=auto,
                technical_impact=impact,
            )
            == expected
        )

    def test_invalid_technical_impact_rejected(self):
        with pytest.raises(ValueError, match="partial.*total"):
            bod_timeline(
                in_kev=False,
                publicly_exposed=False,
                automatable=False,
                technical_impact="high",
            )

    def test_non_boolean_decision_point_rejected(self):
        with pytest.raises(ValueError, match="in_kev must be true or false"):
            bod_timeline(
                in_kev="no",
                publicly_exposed=False,
                automatable=False,
                technical_impact="partial",
            )

    def test_escalation_only_for_a2(self):
        for cls in ("A0", "A1"):
            assert escalate("60D", cls) == "60D"
        assert escalate("60D", "A2") == "14D"

    def test_escalation_never_adds_forensic_triage(self):
        """Forensic triage is a CISA determination; AIVSS must not impose it."""
        for timeline in TIMELINE_URGENCY:
            assert escalate(timeline, "A2") != "3DF" or timeline == "3DF"
        assert escalate("3D", "A2") == "3D"
        assert escalate("3DF", "A2") == "3DF"

    def test_escalation_advances_exactly_one_tier(self):
        assert escalate("FSU", "A2") == "60D"
        assert escalate("14D", "A2") == "3D"

    def test_td_high_does_not_escalate_timeline_v1_overlay(self):
        """v1.0 SSVC overlay: only A2 escalates; TD/TA is metadata only."""
        assert advance_timeline("60D", 1) == "14D"
        result = decide(
            evidence=ExploitationEvidence(),
            publicly_exposed=False,
            **DECISION_CONTEXT,
            agentic_effect_class="A0",
            td="H",
            automatable=False,
            technical_impact="partial",
        )
        assert result["bod_2604_analogy_timeline"] == "FSU"
        assert result["aivss_recommended_timeline"] == "FSU"
        assert result["overlay_triggered"] is False
        assert result["escalated"] is False

    def test_a2_escalates_timeline_one_tier(self):
        result = decide(
            evidence=ExploitationEvidence(),
            publicly_exposed=False,
            **DECISION_CONTEXT,
            agentic_effect_class="A2",
            td="H",
            automatable=False,
            technical_impact="partial",
        )
        assert result["bod_2604_analogy_timeline"] == "FSU"
        assert result["aivss_recommended_timeline"] == "60D"
        assert result["overlay_triggered"] is True
        assert result["escalated"] is True

    def test_forensic_triage_is_never_removed(self):
        result = decide(
            evidence=ExploitationEvidence(cisa_kev=True),
            cve_id="CVE-2026-12345",
            fceb_bod_2604_scope=True,
            publicly_exposed=True,
            **DECISION_CONTEXT,
            vulnrichment_automatable=True,
            vulnrichment_technical_impact="total",
            agentic_effect_class="A2",
            td="H",
        )
        assert result["bod_2604_timeline"] == "3DF"
        assert result["aivss_recommended_timeline"] == "3DF"
        assert result["forensic_triage_required"] is True
        assert result["aivss_recommended_forensic_triage_indicated"] is True


class TestEvidenceLadder:
    def test_kev_outranks_everything(self):
        result = ExploitationEvidence(
            cisa_kev=True, epss=0.01, epss_date="2026-08-27", poc=True
        ).resolve()
        assert result["rung"] == "cisa_kev"
        assert result["authoritative"] is True

    def test_precedence_order(self):
        assert ExploitationEvidence(vulnrichment_active=True, poc=True).resolve()[
            "rung"
        ] == ("vulnrichment_active")
        assert ExploitationEvidence(observed_local=True, poc=True).resolve()[
            "rung"
        ] == ("observed_local")
        assert ExploitationEvidence(poc=True).resolve()["rung"] == "poc"
        assert ExploitationEvidence().resolve()["rung"] == "none"

    def test_epss_does_not_determine_exploitation_state(self):
        result = ExploitationEvidence(epss=0.99, epss_date="2026-08-27").resolve()
        assert result["rung"] == "none"
        assert result["epss"] == 0.99

    def test_observed_local_outranks_epss(self):
        result = ExploitationEvidence(
            epss=0.99, epss_date="2026-08-27", observed_local=True
        ).resolve()
        assert result["rung"] == "observed_local"

    def test_locally_observed_is_not_authoritative(self):
        assert (
            ExploitationEvidence(observed_local=True).resolve()["authoritative"]
            is False
        )

    def test_epss_requires_an_observation_date(self):
        with pytest.raises(ValueError, match="epss_date is required"):
            ExploitationEvidence(epss=0.42)

    def test_epss_used_as_published(self):
        """No transform: the raw probability is carried through unchanged."""
        assert (
            ExploitationEvidence(epss=0.42, epss_date="2026-08-27").resolve()["epss"]
            == 0.42
        )

    def test_epss_range_validated(self):
        with pytest.raises(ValueError, match=r"\[0.0, 1.0\]"):
            ExploitationEvidence(epss=1.5, epss_date="2026-08-27")

    def test_epss_date_is_strict_iso_date(self):
        with pytest.raises(ValueError, match="YYYY-MM-DD"):
            ExploitationEvidence(epss=0.42, epss_date="20260827")

    def test_evidence_flags_are_strict_booleans(self):
        with pytest.raises(ValueError, match="cisa_kev must be true, false, or omitted"):
            ExploitationEvidence(cisa_kev="yes")

    def test_non_cve_requires_explicit_analogy_inputs(self):
        with pytest.raises(ValueError, match="automatable is required"):
            decide(
                evidence=ExploitationEvidence(),
                publicly_exposed=True,
                **DECISION_CONTEXT,
                agentic_effect_class="A0",
            )

    def test_cve_uses_bod_defaults_when_metadata_is_missing(self):
        result = decide(
            evidence=ExploitationEvidence(cisa_kev=False),
            publicly_exposed=True,
            **DECISION_CONTEXT,
            agentic_effect_class="A0",
            cve_id="CVE-2024-0001",
        )
        assert result["decision_points"]["automatable"] is False
        assert (
            result["decision_points"]["automatable_source"] == "BOD 26-04 default (no)"
        )
        assert result["decision_points"]["technical_impact"] == "total"
        assert result["compliance_applicable"] is False
        assert result["decision_basis"] == "informative_bod_26_04_cve_guidance"

    def test_kev_requires_published_metadata_instead_of_defaults(self):
        with pytest.raises(ValueError, match="require CISA Vulnrichment"):
            decide(
                evidence=ExploitationEvidence(cisa_kev=True),
                publicly_exposed=True,
                **DECISION_CONTEXT,
                cve_id="CVE-2026-12345",
            )

    def test_non_cve_result_is_never_labelled_compliance(self):
        result = decide(
            evidence=ExploitationEvidence(),
            publicly_exposed=False,
            **DECISION_CONTEXT,
            automatable=False,
            technical_impact="partial",
        )
        assert result["decision_basis"] == "informative_bod_26_04_analogy"
        assert result["compliance_applicable"] is False
        assert "bod_2604_timeline" not in result

    def test_unmodified_bod_timeline_always_reported(self):
        result = decide(
            evidence=ExploitationEvidence(cisa_kev=True),
            cve_id="CVE-2026-12345",
            fceb_bod_2604_scope=True,
            publicly_exposed=False,
            **DECISION_CONTEXT,
            agentic_effect_class="A2",
            td="M",
            vulnrichment_automatable=False,
            vulnrichment_technical_impact="partial",
        )
        assert result["bod_2604_timeline"] == "14D"
        assert result["aivss_recommended_timeline"] == "3D"
        assert result["escalated"] is True


class TestTaxonomy:
    def test_ten_asi_categories(self):
        assert len(ASI_TOP_10) == 10
        assert list(ASI_TOP_10) == [f"ASI{i:02d}" for i in range(1, 11)]

    def test_v08_crosswalk_resolves(self):
        assert normalize_asi("Agentic AI Tool Misuse") == "ASI02"
        assert normalize_asi("asi06") == "ASI06"

    def test_untraceability_has_no_asi_successor(self):
        with pytest.raises(ValueError, match="TD"):
            normalize_asi("Agent Untraceability")

    def test_every_crosswalk_target_is_valid(self):
        for target in V08_CATEGORY_CROSSWALK.values():
            assert target is None or target in ASI_TOP_10

    def test_unknown_category_rejected(self):
        with pytest.raises(ValueError, match="Unknown risk category"):
            normalize_asi("Not A Category")


class TestPriority:
    def test_geometric_mean(self):
        result = compute_priority(
            severity=8.0, business_criticality="high", reach="high", likelihood=0.72
        )
        assert result["aivss_p"] == 87

    def test_zero_likelihood_yields_zero(self):
        assert compute_priority(severity=10.0, likelihood=0.0)["aivss_p"] == 0

    def test_maximum_reaches_100(self):
        assert (
            compute_priority(
                severity=10.0, business_criticality="high", reach="high", likelihood=1.0
            )["aivss_p"]
            == 100
        )

    def test_critical_severity_with_median_context_is_not_backlogged(self):
        """The withdrawn Track P returned 'Track' here, which was indefensible."""
        result = compute_priority(severity=9.5, likelihood=0.5)
        assert result["band"] != "Backlog"

    def test_monotone_in_every_term(self):
        base = compute_priority(severity=5.0, likelihood=0.5)["aivss_p"]
        assert compute_priority(severity=6.0, likelihood=0.5)["aivss_p"] > base
        assert compute_priority(severity=5.0, likelihood=0.6)["aivss_p"] > base
        assert (
            compute_priority(severity=5.0, business_criticality="high", likelihood=0.5)[
                "aivss_p"
            ]
            > base
        )

    def test_invalid_inputs_rejected(self):
        with pytest.raises(ValueError):
            compute_priority(severity=11.0)
        with pytest.raises(ValueError):
            compute_priority(severity=5.0, likelihood=2.0)
        with pytest.raises(ValueError, match="business_criticality"):
            compute_priority(severity=5.0, business_criticality="critical")


class TestLegacyAnnexB:
    ALL_FACTORS = {
        name: 0.5
        for name in (
            "autonomy",
            "tools",
            "language",
            "context",
            "non_determinism",
            "opacity",
            "persistence",
            "identity",
            "multi_agent",
            "self_mod",
        )
    }

    def test_floor_guarantee_exhaustive(self):
        """AIVSS_S >= CVSS_Base for every combination, including after rounding."""
        for c in range(0, 101):
            cvss = c / 10
            for fs in (0.0, 0.1, 0.35, 0.5, 0.85, 1.0):
                for thm in (0.50, 0.97, 1.00):
                    for mf in (1.0, 0.83, 0.67, 0.50):
                        aars = (10.0 - cvss) * fs * thm
                        score = compute_severity(cvss, aars, mf)
                        assert cvss <= score <= 10.0

    def test_v08_defect_is_repaired(self):
        result = score_legacy(
            cvss_base=9.0,
            factors={**self.ALL_FACTORS, **{k: 0.0 for k in self.ALL_FACTORS}},
            threat_maturity="poc",
            mitigation_inherent="strong",
        )
        assert result["v08_unrepaired"] < result["cvss_base"]
        assert result["aivss_s_inherent"] >= result["cvss_base"]

    def test_missing_factor_is_an_error(self):
        with pytest.raises(ValueError, match="Missing amplification factor"):
            factor_mean({"autonomy": 1.0})

    def test_unknown_factor_is_an_error(self):
        with pytest.raises(ValueError, match="Unknown amplification factor"):
            factor_mean({**self.ALL_FACTORS, "bogus": 1.0})

    def test_non_rubric_value_is_an_error(self):
        with pytest.raises(ValueError, match="must be 0.0, 0.5, or 1.0"):
            factor_mean({**self.ALL_FACTORS, "autonomy": 0.65})

    def test_unknown_enum_values_are_errors(self):
        with pytest.raises(ValueError, match="Unknown threat maturity"):
            score_legacy(
                cvss_base=5.0, factors=self.ALL_FACTORS, threat_maturity="typo"
            )
        with pytest.raises(ValueError, match="Unknown mitigation strength"):
            score_legacy(
                cvss_base=5.0, factors=self.ALL_FACTORS, mitigation_inherent="storng"
            )

    def test_cvss_base_precision_validated(self):
        with pytest.raises(ValueError, match="one decimal place"):
            score_legacy(cvss_base=6.14, factors=self.ALL_FACTORS)

    def test_no_category_weights(self):
        """The uncalibrated category weight table is withdrawn."""
        import aivss_calc.legacy as legacy

        assert not hasattr(legacy, "OWASP_CATEGORIES")

    def test_cvss_sensitivity_is_reported(self):
        result = score_legacy(
            cvss_base=6.1,
            factors={k: 1.0 for k in self.ALL_FACTORS},
            threat_maturity="poc",
        )
        assert result["cvss_sensitivity"] == pytest.approx(0.03, abs=0.001)


class TestEndToEnd:
    def _assessment(self, **overrides):
        defaults = dict(
            finding_id="AIVSS-EX-001",
            path_id="AIVSS-EX-001-PATH-1",
            cvss_vector=EXAMPLE_VECTOR,
            aivss_vector=EXAMPLE_AI,
            asi_category="ASI06",
            agentic_applicability=dict(APPLICABILITY),
            metric_evidence=dict(METRIC_EVIDENCE),
            evidence=ExploitationEvidence(poc=True),
            publicly_exposed=True,
            publicly_exposed_source="test fixture",
            decision_data_observed_at="2026-08-27T00:00:00Z",
            automatable=True,
            technical_impact="total",
            org_context=OrgContext(
                business_criticality="high", reach="high", likelihood=0.72
            ),
            include_priority=True,
            provenance=Provenance(
                assessor="test",
                tool="aivss-calc",
                tool_version="1.0.0",
                assessed_at="2026-08-27T00:00:00Z",
            ),
        )
        if "aivss_vector" in overrides and "metric_evidence" not in overrides:
            overrides["metric_evidence"] = metric_evidence(overrides["aivss_vector"])
        defaults.update(overrides)
        return assess(Assessment(**defaults))

    def test_candidate_adjustment_is_transparent(self):
        report = self._assessment()
        assert report["cvss"]["cvss_bte"] == EXAMPLE_CVSS_BTE
        candidate = report["scores"]["candidate_adjusted"]
        assert candidate["ex_delta"] == EXAMPLE_EX_DELTA
        assert candidate["pt_delta"] == EXAMPLE_PT_DELTA
        assert candidate["ca_delta"] == EXAMPLE_CA_DELTA
        assert candidate["td_delta"] == EXAMPLE_TD_DELTA
        assert candidate["agentic_risk_delta"] == EXAMPLE_AGENTIC_RISK_DELTA
        assert candidate["aivss"] == EXAMPLE_AIVSS
        assert candidate["raw_aivss"] == EXAMPLE_AIVSS

    def test_macrovector_experiment_is_off_by_default(self):
        assert "experimental_macrovector" not in self._assessment()["scores"]

    def test_macrovector_experiment_is_explicitly_uncalibrated(self):
        report = self._assessment(include_experimental_mode2=True)
        experiment = report["scores"]["experimental_macrovector"]
        assert experiment["aivss_btea"] == 10.0
        assert experiment["btea_before_agentic_risk"] == 9.0
        assert experiment["status"] == "experimental-uncalibrated"

    def test_vectors_are_separate(self):
        report = self._assessment()
        assert report["cvss"]["vector"] == EXAMPLE_VECTOR
        assert report["agentic_ai_profile"]["vector"] == EXAMPLE_AI
        assert "vector" not in report

    def test_a0_is_value_based_not_presence_based(self):
        benign = "AIVSS:1.0/LC:N/CP:N/AP:N/SR:U/EX:W/PT:L/CA:N/TD:H"
        report = self._assessment(aivss_vector=benign)
        assert report["agentic_ai_profile"]["agentic_effect_class"] == "A0"
        assert report["scores"]["candidate_adjusted"]["aivss"] == 8.7

    def test_assess_without_profile_rejected(self):
        with pytest.raises(ValueError, match="eight"):
            assess(
                Assessment(
                    finding_id="x",
                    path_id="x-path",
                    cvss_vector=EXAMPLE_VECTOR,
                    asi_category="ASI06",
                    agentic_applicability=dict(APPLICABILITY),
                    publicly_exposed=True,
                )
            )

    def test_priority_omitted_when_not_requested(self):
        assert "priority" not in self._assessment(include_priority=False)

    def test_decision_requires_publicly_exposed(self):
        with pytest.raises(ValueError, match="publicly_exposed"):
            assess(
                Assessment(
                    finding_id="x",
                    path_id="x-path",
                    cvss_vector=EXAMPLE_VECTOR,
                    aivss_vector=EXAMPLE_AI,
                    asi_category="ASI06",
                    agentic_applicability=dict(APPLICABILITY),
                    metric_evidence=dict(METRIC_EVIDENCE),
                    include_decision=True,
                    provenance=Provenance(assessed_at="2026-08-27T00:00:00Z"),
                )
            )

    def test_report_validates_against_schema(self):
        validate_report(self._assessment())

    def test_shipped_example_validates_against_schema(self):
        example = pathlib.Path(__file__).parents[1] / "examples" / "asi06-example.json"
        data = json.loads(example.read_text(encoding="utf-8"))
        validate_assessment_input(data)
        report = assess(assessment_from_payload(data))
        validate_report(report)
        assert report["scores"]["candidate_adjusted"]["aivss"] == EXAMPLE_AIVSS
