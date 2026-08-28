"""CVSS v4.0 BTE scoring via the Red Hat reference implementation.

The vendored MacroVector lookup table stores each equivalence class's
*highest-severity* score. A specific vector within a class is scored lower via
CVSS v4 interpolation. Mode 1 and the Appendix E identity rule require the
interpolated score, not the MacroVector ceiling.
"""

from __future__ import annotations

import math

from cvss import CVSS4


def round_half_up(value: float, decimals: int = 1) -> float:
    multiplier = 10**decimals
    return math.floor(value * multiplier + 0.5) / multiplier


def score_cvss_bte(cvss_vector: str) -> float:
    """Return the CVSS v4.0 Base+Threat+Environmental score for a vector."""
    try:
        return float(CVSS4(cvss_vector.strip()).scores()[0])
    except Exception as exc:
        raise ValueError(f"Cannot score CVSS vector: {exc}") from exc
