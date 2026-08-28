"""Optional Level 3 organizational priority index (AIVSS-P).

Organization-internal and non-portable. AIVSS-P orders work within one
portfolio; it is not comparable across organizations and must not be published
outside the assessing organization.

Rebuilt from the withdrawn v0.9 Track P, which had three defects:

* It multiplied a Threat Multiplier term that was already inside the severity
  input, and business criticality and control strength each appeared twice.
  Here every quantity is priced exactly once, and exploitation is priced
  nowhere -- that belongs to the Decision Track.
* Multiplying five sub-unit terms pushed 88% of plausible inputs into the
  bottom band, so a Critical finding with median context returned "Track". A
  geometric mean over the terms restores the dynamic range while preserving
  ordering.
* It required sixteen OWASP Risk Rating factors per finding. Likelihood is now
  a single organization-supplied value; organizations should derive it with
  their existing methodology (NIST SP 800-30 Rev. 1 or equivalent).
"""

from __future__ import annotations

import math

CONTEXT_LEVELS: dict[str, float] = {"high": 1.0, "medium": 0.65, "low": 0.35}


def _level(name: str, value: str) -> float:
    key = str(value).strip().lower()
    if key not in CONTEXT_LEVELS:
        raise ValueError(
            f"{name} must be one of {sorted(CONTEXT_LEVELS)}; got {value!r}"
        )
    return CONTEXT_LEVELS[key]


def compute_priority(
    *,
    severity: float,
    business_criticality: str = "medium",
    reach: str = "medium",
    likelihood: float = 0.5,
) -> dict[str, object]:
    """AIVSS-P = 100 x geometric_mean(S/10, BI, REACH, L).

    Terms, each pricing one quantity exactly once:
      S/10   technical severity, from CVSS-BTE or AIVSS-BTEA
      BI     business criticality of the affected asset
      REACH  deployment reach
      L      organization-assessed likelihood
    """
    if not 0.0 <= severity <= 10.0:
        raise ValueError(f"severity must be in [0.0, 10.0]; got {severity}")
    if not 0.0 <= likelihood <= 1.0:
        raise ValueError(f"likelihood must be in [0.0, 1.0]; got {likelihood}")

    bi = _level("business_criticality", business_criticality)
    re = _level("reach", reach)

    terms = {
        "severity_norm": severity / 10.0,
        "business_criticality": bi,
        "reach": re,
        "likelihood": likelihood,
    }

    if any(v <= 0.0 for v in terms.values()):
        score = 0
    else:
        gm = math.exp(sum(math.log(v) for v in terms.values()) / len(terms))
        score = math.floor(100 * gm + 0.5)

    return {
        "aivss_p": score,
        "band": priority_band(score),
        "terms": {k: round(v, 4) for k, v in terms.items()},
        "scope": "organization-internal; not comparable across organizations",
    }


def priority_band(score: int) -> str:
    """Bands set from the output distribution rather than assumed.

    Cut-points are the p90/p65/p35 quantiles of AIVSS-P over a uniform grid of
    severity 4.0-10.0 x business criticality x reach x likelihood (n=10,980),
    giving roughly 10/25/30/35 percent occupancy. That grid over-represents
    high-severity findings relative to a real portfolio, so organizations
    should recalibrate these cut-points against their own corpus before using
    them to drive commitments.
    """
    if score >= 78:
        return "Immediate"
    if score >= 64:
        return "This sprint"
    if score >= 53:
        return "Scheduled"
    return "Backlog"
