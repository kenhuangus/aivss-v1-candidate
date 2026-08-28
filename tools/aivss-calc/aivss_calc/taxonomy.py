"""OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10).

Canonical risk taxonomy for AIVSS, per Appendix E section 1: "use the existing
OWASP Agentic AI / LLM Top 10 as the canonical risk taxonomy".

Published 2025-12-09 by the OWASP GenAI Security Project.
"""

from __future__ import annotations

ASI_TOP_10: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

# Crosswalk from the withdrawn AIVSS v0.8 category list. ASI09 and ASI10 have no
# v0.8 predecessor. "Agent Untraceability" has no ASI successor in OWASP Top 10;
# AIVSS retains it as the mandatory TD (Traceability Deficit) risk factor — credit
# to the OWASP AIVSS project taxonomy.
V08_CATEGORY_CROSSWALK: dict[str, str | None] = {
    "Agent Goal and Instruction Manipulation": "ASI01",
    "Agentic AI Tool Misuse": "ASI02",
    "Agent Access Control Violation": "ASI03",
    "Agent Identity Impersonation": "ASI03",
    "Agent Supply Chain and Dependency Risk": "ASI04",
    "Insecure Agent Critical Systems Interaction": "ASI05",
    "Agent Memory and Context Manipulation": "ASI06",
    "Agent Orchestration and Multi-Agent Exploitation": "ASI07",
    "Agent Cascading Failures": "ASI08",
    "Agent Untraceability": None,
}


def normalize_asi(value: str) -> str:
    """Resolve an ASI id or a withdrawn v0.8 category name to an ASI id."""
    candidate = value.strip()
    upper = candidate.upper()
    if upper in ASI_TOP_10:
        return upper
    if candidate in V08_CATEGORY_CROSSWALK:
        mapped = V08_CATEGORY_CROSSWALK[candidate]
        if mapped is None:
            raise ValueError(
                f"v0.8 category {candidate!r} has no ASI equivalent. Assess Agent "
                "Untraceability via the mandatory TD (Traceability Deficit) metric "
                "(credit: OWASP AIVSS taxonomy)"
            )
        return mapped
    raise ValueError(
        f"Unknown risk category {value!r}. Expected one of {sorted(ASI_TOP_10)} "
        "or a withdrawn AIVSS v0.8 category name."
    )
