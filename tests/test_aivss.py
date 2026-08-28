"""Conformance and regression tests for the AIVSS v1.0 reference calculator.

Assertions are exact. A scoring standard whose own tests carry wide tolerances
cannot arbitrate between two implementations that disagree.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from aivss_calc import (
    BOD_2604_TABLE,
    AIProfile,
    Assessment,
    ExploitationEvidence,
    OrgContext,
    Provenance,
    assess,
    bod_timeline,
    compute_priority,
    lookup_aivss,
    macrovector,
    macrovector_score,
    normalize_asi,
    parse_cvss_vector,
    promote,
    split_ai_vector,
)
from aivss_calc.ai_metrics import apply_td_risk, td_risk_delta
from aivss_calc.decision import TIMELINE_URGENCY, advance_timeline, decide, escalate
from aivss_calc.legacy import compute_severity, factor_mean, score_legacy
from aivss_calc.cvss_score import score_cvss_bte
from aivss_calc.macrovector import _lookup_table
from aivss_calc.taxonomy import ASI_TOP_10, V08_CATEGORY_CROSSWALK

REPO = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = REPO / "schemas" / "aivss-report-v1.0.json"

# CVSS-BTE 7.8 (interpolated), MacroVector ceiling 8.0.
EXAMPLE_VECTOR = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P"
EXAMPLE_CVSS_BTE = 7.8
EXAMPLE_TD_DELTA = 0.5
EXAMPLE_AIVSS = 8.3
EXAMPLE_AI = "LC:D/CP:C/AP:L/SR:R/TD:H"
EXAMPLE_FULL = f"{EXAMPLE_VECTOR}/{EXAMPLE_AI}"


class TestMacroVectorTable:
    def test_has_270_equivalence_classes(self):
        assert len(_lookup_table()) == 270

    def test_joint_eq3_eq6_constraint(self):
        assert not [k for k in _lookup_table() if k[2] == "2" and k[5] == "0"]

    def test_scores_within_range(self):
        assert all(0.0 <= v <= 10.0 for v in _lookup_table().values())


class TestIdentityRule:
    """Appendix E section 5.2: Lookup_AIVSS(EQ1..EQ6, A0) == CVSS-BTE."""

    def test_identity_holds_for_every_macrovector(self):
        table = _lookup_table()
        for mv, score in table.items():
            assert promote(mv, "A0") == mv
            assert macrovector_score(promote(mv, "A0")) == score

    def test_absent_ai_metrics_yield_a0(self):
        metrics = parse_cvss_vector(EXAMPLE_VECTOR)
        result = lookup_aivss(EXAMPLE_VECTOR, metrics, "A0")
        assert result["ai_class"] == "A0"
        assert result["aivss_btea"] == EXAMPLE_CVSS_BTE
        assert result["delta"] == 0.0

    def test_td_risk_delta_adjusts_score(self):
        """TD (Traceability Deficit) is mandatory and adjusts the published AIVSS score."""
        metrics = parse_cvss_vector(EXAMPLE_VECTOR)
        base = lookup_aivss(EXAMPLE_VECTOR, metrics, "A0")["aivss_btea"]
        for td, delta in (("H", 0.5), ("M", 0.2), ("L", 0.0)):
            profile = AIProfile(td=td, scored_present=False)
            assert profile.effect_class() == "A0"
            assert td_risk_delta(td) == delta
            assert apply_td_risk(base, td) == round(min(10.0, base + delta), 1)

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
        assert all(macrovector_score(promote(mv, "A2")) <= 10.0 for mv in _lookup_table())

    def test_unknown_class_rejected(self):
        with pytest.raises(ValueError, match="Unknown AI Effect Class"):
            promote("000000", "A3")


class TestAIEffectClass:
    def test_appendix_e_worked_example(self):
        """Appendix E section 9.2 asserts LC:D and CP:C imply A2."""
        assert AIProfile(lc="D", cp="C", ap="N", sr="U").effect_class() == "A2"

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
        assert AIProfile(**kwargs).effect_class() == "A2"

    @pytest.mark.parametrize(
        "kwargs",
        [{"lc": "I"}, {"cp": "S"}, {"ap": "C"}, {"sr": "R"}, {"lc": "M"}],
    )
    def test_a1_conditions(self, kwargs):
        assert AIProfile(**kwargs).effect_class() == "A1"

    def test_a0_only_when_all_benign(self):
        assert AIProfile(lc="N", cp="N", ap="N", sr="U").effect_class() == "A0"

    def test_every_combination_yields_a_valid_class(self):
        for lc in "DIMN":
            for cp in "CSN":
                for ap in "LCN":
                    for sr in "RPU":
                        cls = AIProfile(lc=lc, cp=cp, ap=ap, sr=sr).effect_class()
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
                                    order[AIProfile(**hi).effect_class()]
                                    >= order[AIProfile(**lo).effect_class()]
                                )

    def test_illegal_value_rejected(self):
        with pytest.raises(ValueError, match="Illegal value"):
            AIProfile(lc="Z")


class TestVectorParsing:
    def test_round_trip(self):
        cvss, profile = split_ai_vector(f"{EXAMPLE_VECTOR}/{EXAMPLE_AI}")
        assert cvss == EXAMPLE_VECTOR
        assert profile is not None
        assert profile.to_vector_fragment() == EXAMPLE_AI

    def test_no_ai_group_returns_none(self):
        cvss, profile = split_ai_vector(EXAMPLE_VECTOR)
        assert cvss == EXAMPLE_VECTOR
        assert profile is None

    def test_partial_ai_group_rejected(self):
        with pytest.raises(ValueError, match="all four scored metrics"):
            split_ai_vector(f"{EXAMPLE_VECTOR}/LC:D/CP:C")

    def test_scored_ai_group_without_td_rejected(self):
        with pytest.raises(ValueError, match="TD"):
            split_ai_vector(f"{EXAMPLE_VECTOR}/LC:D/CP:C/AP:L/SR:R")

    def test_duplicate_ai_metric_rejected(self):
        with pytest.raises(ValueError, match="Duplicate AI metric"):
            split_ai_vector(f"{EXAMPLE_VECTOR}/LC:D/LC:I/CP:C/AP:L/SR:R")

    @pytest.mark.parametrize(
        "vector,match",
        [
            ("CVSS:3.1/AV:N", "must begin with"),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/ZZ:Q", "Unknown"),
            ("CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "Illegal value"),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N", "Missing mandatory"),
            ("CVSS:4.0/AV:N/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "Duplicate"),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA", "Malformed"),
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
    def test_all_sixteen_rows_present(self):
        assert len(BOD_2604_TABLE) == 16

    def test_kev_plus_total_without_exposure_or_automation_is_14_days(self):
        """Regression: the fast tier needs exposure or automatability, not just
        KEV plus total impact. Hand-written boolean logic gets this wrong."""
        assert (
            bod_timeline(
                in_kev=True, publicly_exposed=False, automatable=False, technical_impact="total"
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
                in_kev=False, publicly_exposed=False, automatable=False, technical_impact="high"
            )

    def test_escalation_only_for_a2(self):
        for cls in ("A0", "A1"):
            assert escalate("60D", cls) == "60D"
        assert escalate("60D", "A2") == "14D"

    def test_escalation_never_reaches_forensic_triage(self):
        """Forensic triage is a CISA determination; AIVSS must not impose it."""
        for timeline in TIMELINE_URGENCY:
            assert escalate(timeline, "A2") != "3DF" or timeline == "3DF"
        assert escalate("3D", "A2") == "3D"

    def test_escalation_advances_exactly_one_tier(self):
        assert escalate("FSU", "A2") == "60D"
        assert escalate("14D", "A2") == "3D"

    def test_td_high_advances_timeline_one_tier(self):
        assert advance_timeline("60D", 1) == "14D"
        result = decide(
            evidence=ExploitationEvidence(),
            publicly_exposed=False,
            ai_class="A0",
            td="H",
            automatable=False,
            technical_impact="partial",
        )
        assert result["bod_2604_timeline"] == "FSU"
        assert result["aivss_recommended_timeline"] == "60D"
        assert result["escalated"] is True


class TestEvidenceLadder:
    def test_kev_outranks_everything(self):
        result = ExploitationEvidence(
            cisa_kev=True, epss=0.01, epss_date="2026-08-27", poc=True
        ).resolve()
        assert result["rung"] == "cisa_kev"
        assert result["authoritative"] is True

    def test_precedence_order(self):
        assert ExploitationEvidence(vulnrichment_active=True, poc=True).resolve()["rung"] == (
            "vulnrichment_active"
        )
        assert ExploitationEvidence(observed_local=True, poc=True).resolve()["rung"] == (
            "observed_local"
        )
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
        assert ExploitationEvidence(observed_local=True).resolve()["authoritative"] is False

    def test_epss_requires_an_observation_date(self):
        with pytest.raises(ValueError, match="epss_date is required"):
            ExploitationEvidence(epss=0.42)

    def test_epss_used_as_published(self):
        """No transform: the raw probability is carried through unchanged."""
        assert ExploitationEvidence(epss=0.42, epss_date="2026-08-27").resolve()["epss"] == 0.42

    def test_epss_range_validated(self):
        with pytest.raises(ValueError, match=r"\[0.0, 1.0\]"):
            ExploitationEvidence(epss=1.5, epss_date="2026-08-27")

    def test_automatable_derived_from_sr_for_non_cve(self):
        result = decide(
            evidence=ExploitationEvidence(),
            publicly_exposed=True,
            ai_class="A0",
            sr="R",
            cvss_metrics=parse_cvss_vector(EXAMPLE_VECTOR),
        )
        assert result["decision_points"]["automatable"] is True
        assert result["decision_points"]["automatable_source"] == "derived from SR (non-CVE finding)"

    def test_automatable_not_derived_from_sr_when_cve_present(self):
        result = decide(
            evidence=ExploitationEvidence(),
            publicly_exposed=True,
            ai_class="A0",
            sr="R",
            cve_id="CVE-2024-0001",
            cvss_metrics=parse_cvss_vector(EXAMPLE_VECTOR),
        )
        assert result["decision_points"]["automatable"] is False
        assert result["decision_points"]["automatable_source"] == "BOD 26-04 default (no)"

    def test_bod_default_when_no_data(self):
        result = decide(evidence=ExploitationEvidence(), publicly_exposed=False)
        points = result["decision_points"]
        assert points["automatable"] is False
        assert points["technical_impact"] == "total"

    def test_unmodified_bod_timeline_always_reported(self):
        result = decide(
            evidence=ExploitationEvidence(cisa_kev=True),
            publicly_exposed=False,
            ai_class="A2",
            automatable=False,
            technical_impact="partial",
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
            compute_priority(severity=5.0, business_criticality="high", likelihood=0.5)["aivss_p"]
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
            "autonomy", "tools", "language", "context", "non_determinism",
            "opacity", "persistence", "identity", "multi_agent", "self_mod",
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
            score_legacy(cvss_base=5.0, factors=self.ALL_FACTORS, threat_maturity="typo")
        with pytest.raises(ValueError, match="Unknown mitigation strength"):
            score_legacy(cvss_base=5.0, factors=self.ALL_FACTORS, mitigation_inherent="storng")

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
            cvss_vector=EXAMPLE_FULL,
            asi_category="ASI06",
            ai_profile=AIProfile(lc="D", cp="C", ap="L", sr="R", td="H"),
            evidence=ExploitationEvidence(poc=True),
            publicly_exposed=True,
            org_context=OrgContext(business_criticality="high", reach="high", likelihood=0.72),
            include_priority=True,
            provenance=Provenance(assessor="test", tool="aivss-calc", tool_version="1.0.0"),
        )
        defaults.update(overrides)
        return assess(Assessment(**defaults))

    def test_mode1_applies_td_risk_delta(self):
        report = self._assessment()
        assert report["cvss"]["cvss_bte"] == EXAMPLE_CVSS_BTE
        assert report["scores"]["mode1_interpretation"]["td_delta"] == EXAMPLE_TD_DELTA
        assert report["scores"]["mode1_interpretation"]["aivss"] == EXAMPLE_AIVSS

    def test_mode2_is_provisional_and_higher(self):
        report = self._assessment()
        assert report["scores"]["mode2_macrovector"]["aivss_btea"] == 9.5
        assert report["scores"]["mode2_macrovector"]["btea_before_td"] == 9.0
        assert report["scores"]["mode2_macrovector"]["status"].startswith("provisional")

    def test_vector_carries_ai_group(self):
        assert self._assessment()["vector"].endswith(EXAMPLE_AI)

    def test_td_only_yields_identity_and_a0(self):
        td_only = f"{EXAMPLE_VECTOR}/TD:H"
        report = self._assessment(cvss_vector=td_only, ai_profile=None)
        assert report["ai_profile"]["present"] is False
        assert report["ai_profile"]["effect_class"] == "A0"
        assert report["scores"]["mode2_macrovector"]["btea_before_td"] == EXAMPLE_CVSS_BTE
        assert report["scores"]["mode2_macrovector"]["aivss_btea"] == EXAMPLE_AIVSS
        assert report["scores"]["mode1_interpretation"]["aivss"] == EXAMPLE_AIVSS

    def test_assess_without_td_rejected(self):
        with pytest.raises(ValueError, match="TD"):
            assess(
                Assessment(
                    finding_id="x",
                    cvss_vector=EXAMPLE_VECTOR,
                    asi_category="ASI06",
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
                    cvss_vector=f"{EXAMPLE_VECTOR}/TD:H",
                    asi_category="ASI06",
                    include_decision=True,
                )
            )

    def test_report_validates_against_schema(self):
        jsonschema = pytest.importorskip("jsonschema")
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        jsonschema.validate(self._assessment(), schema)

    def test_shipped_example_validates_against_schema(self):
        jsonschema = pytest.importorskip("jsonschema")
        example = pathlib.Path(__file__).parents[1] / "examples" / "asi06-memory-poisoning.json"
        data = json.loads(example.read_text(encoding="utf-8"))
        report = assess(
            Assessment(
                finding_id=data["finding_id"],
                cvss_vector=data["cvss_vector"],
                asi_category=data["risk_category"],
                evidence=ExploitationEvidence(**data["evidence"]),
                org_context=OrgContext(**data["org_context"]),
                provenance=Provenance(**data["provenance"]),
                publicly_exposed=data["publicly_exposed"],
                include_decision=data.get("include_decision", True),
                include_priority=data.get("include_priority", False),
            )
        )
        jsonschema.validate(report, json.loads(SCHEMA.read_text(encoding="utf-8")))
        assert report["scores"]["mode1_interpretation"]["aivss"] == EXAMPLE_AIVSS
