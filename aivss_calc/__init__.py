"""AIVSS 1.0 reference calculator.

CVSS severity remains independently reproducible. AIVSS adds a separate
eight-metric profile as parallel metadata.
"""

from .ai_metrics import (
    AGENTIC_EFFECT_CLASS_LABELS,
    AI_METRIC_ORDER,
    AI_METRICS,
    AIProfile,
    SRClassification,
    classify_ca,
    classify_sr,
    classify_td,
    parse_aivss_vector,
    split_ai_vector,
    validate_metric_evidence,
)
from .assessment import (
    Assessment,
    OrgContext,
    Provenance,
    assess,
    assessment_from_payload,
)
from .decision import (
    BOD_2604_TABLE,
    TIMELINE_LABELS,
    ExploitationEvidence,
    bod_timeline,
    decide,
)
from .cvss_score import score_cvss_bte
from .macrovector import macrovector, macrovector_score, parse_cvss_vector
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
    "macrovector",
    "macrovector_score",
    "normalize_asi",
    "parse_cvss_vector",
    "priority_band",
    "score_cvss_bte",
    "classify_sr",
    "classify_ca",
    "classify_td",
    "parse_aivss_vector",
    "split_ai_vector",
    "validate_metric_evidence",
]
