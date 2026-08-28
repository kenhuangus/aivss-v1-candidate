"""AIVSS 1.0 reference calculator.

CVSS severity remains independently reproducible. AIVSS adds a separate
eight-metric profile and explicitly experimental candidate calculations.
"""

from .ai_metrics import (
    AGENTIC_EFFECT_CLASS_LABELS,
    AI_METRIC_ORDER,
    AI_METRICS,
    AIProfile,
    SRClassification,
    agentic_risk_delta,
    apply_agentic_risk,
    candidate_adjustment,
    ca_risk_delta,
    classify_ca,
    classify_sr,
    classify_td,
    parse_aivss_vector,
    ex_risk_delta,
    pt_risk_delta,
    split_ai_vector,
    td_risk_delta,
    validate_metric_evidence,
)
from .assessment import (
    Assessment,
    OrgContext,
    Provenance,
    assess,
    assessment_from_payload,
    identity_holds,
)
from .decision import (
    BOD_2604_TABLE,
    TIMELINE_LABELS,
    ExploitationEvidence,
    bod_timeline,
    decide,
)
from .cvss_score import score_cvss_bte
from .macrovector import (
    lookup_aivss,
    macrovector,
    macrovector_score,
    parse_cvss_vector,
    promote,
)
from .priority import compute_priority, priority_band
from .taxonomy import ASI_TOP_10, V08_CATEGORY_CROSSWALK, normalize_asi
from .versions import CALCULATOR_VERSION, SPEC_VERSION

__version__ = CALCULATOR_VERSION

__all__ = [
    "AIProfile",
    "AGENTIC_EFFECT_CLASS_LABELS",
    "AI_METRICS",
    "AI_METRIC_ORDER",
    "ASI_TOP_10",
    "Assessment",
    "BOD_2604_TABLE",
    "ExploitationEvidence",
    "OrgContext",
    "Provenance",
    "SRClassification",
    "SPEC_VERSION",
    "TIMELINE_LABELS",
    "V08_CATEGORY_CROSSWALK",
    "__version__",
    "assess",
    "assessment_from_payload",
    "bod_timeline",
    "compute_priority",
    "decide",
    "identity_holds",
    "lookup_aivss",
    "macrovector",
    "macrovector_score",
    "normalize_asi",
    "parse_cvss_vector",
    "priority_band",
    "promote",
    "score_cvss_bte",
    "agentic_risk_delta",
    "apply_agentic_risk",
    "candidate_adjustment",
    "classify_sr",
    "classify_ca",
    "classify_td",
    "parse_aivss_vector",
    "ca_risk_delta",
    "ex_risk_delta",
    "pt_risk_delta",
    "td_risk_delta",
    "split_ai_vector",
    "validate_metric_evidence",
]
