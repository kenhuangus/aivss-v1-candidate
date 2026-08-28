"""AIVSS v1.0 reference calculator.

Implements the CVSS-compatible AI scoring model: an interpretation mode in which
AIVSS equals CVSS-BTE, a provisional MacroVector extension mode, and a decision
track aligned to CISA BOD 26-04.
"""

from .ai_metrics import (
    AGENTIC_EFFECT_CLASS_LABELS,
    AI_METRIC_ORDER,
    AI_METRICS,
    AIProfile,
    agentic_risk_delta,
    apply_agentic_risk,
    ex_risk_delta,
    split_ai_vector,
    td_risk_delta,
)
from .assessment import (
    SPEC_VERSION,
    Assessment,
    OrgContext,
    Provenance,
    assess,
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

__version__ = "1.1.0"

__all__ = [
    "AIProfile",
    "AI_METRICS",
    "AI_METRIC_ORDER",
    "ASI_TOP_10",
    "Assessment",
    "BOD_2604_TABLE",
    "ExploitationEvidence",
    "OrgContext",
    "Provenance",
    "SPEC_VERSION",
    "TIMELINE_LABELS",
    "V08_CATEGORY_CROSSWALK",
    "__version__",
    "assess",
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
    "ex_risk_delta",
    "td_risk_delta",
    "split_ai_vector",
]
