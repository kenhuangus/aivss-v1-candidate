"""OWASP Agentic AI Top 10 reference scenarios for the AIVSS calculator."""

from __future__ import annotations

from typing import Any

from .taxonomy import ASI_TOP_10

SCENARIOS: list[dict[str, Any]] = [
    {
        "finding_id": "AIVSS-ASI01-001",
        "risk_category": "ASI01",
        "title": "Direct prompt injection hijacks planning agent goals",
        "summary": "Attacker-supplied instructions override the agent's intended goals via a language-mediated control path.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:N/E:P/LC:D/CP:S/AP:C/SR:R/EX:M/TD:M",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI02-001",
        "risk_category": "ASI02",
        "title": "Agent misuses legitimate tool for unauthorized data export",
        "summary": "A compromised or misled agent invokes an authorized tool outside its intended scope.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N/E:P/LC:I/CP:N/AP:C/SR:R/EX:M/TD:L",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI03-001",
        "risk_category": "ASI03",
        "title": "Stolen service credential used for lateral agent actions",
        "summary": "Abuse of agent identity or privileges to act on resources beyond the attacker's direct reach.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/LC:M/CP:N/AP:L/SR:R/EX:M/TD:L",
        "publicly_exposed": False,
        "evidence": {"observed_local": True},
    },
    {
        "finding_id": "AIVSS-ASI04-001",
        "risk_category": "ASI04",
        "title": "Compromised MCP plugin supplies malicious tool definitions",
        "summary": "Untrusted supply-chain component alters agent capabilities or tool schemas at runtime.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:N/E:P/LC:I/CP:N/AP:L/SR:P/EX:W/TD:M",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI05-001",
        "risk_category": "ASI05",
        "title": "Code interpreter executes attacker-supplied shell commands",
        "summary": "Agent reaches a code-execution path and runs attacker-controlled instructions.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/LC:D/CP:N/AP:N/SR:R/EX:M/TD:L",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI06-001",
        "risk_category": "ASI06",
        "title": "Adversarial content in agent memory biases later sessions",
        "summary": "Poisoned context persists across sessions and influences future agent decisions.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P/LC:D/CP:C/AP:L/SR:R/EX:W/TD:H",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI07-001",
        "risk_category": "ASI07",
        "title": "Unsigned agent-to-agent messages allow instruction relay",
        "summary": "Inter-agent messages lack authentication, enabling cross-agent propagation of malicious intent.",
        "cvss_vector": "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:H/SI:L/SA:N/E:P/LC:I/CP:S/AP:L/SR:R/EX:W/TD:M",
        "publicly_exposed": False,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI08-001",
        "risk_category": "ASI08",
        "title": "Faulty planner triggers cascading downstream task failures",
        "summary": "A single agent fault propagates through orchestration to many dependent workflows.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:H/SC:H/SI:H/SA:L/E:P/LC:I/CP:S/AP:L/SR:P/EX:W/TD:H",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI09-001",
        "risk_category": "ASI09",
        "title": "Social engineering of human approver via forged agent summaries",
        "summary": "Attacker exploits human trust in agent-generated summaries to obtain unauthorized approvals.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:N/SC:H/SI:N/SA:N/E:P/LC:D/CP:N/AP:C/SR:P/EX:N/TD:H",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI10-001",
        "risk_category": "ASI10",
        "title": "Compromised worker agent operates outside policy envelope",
        "summary": "A rogue or hijacked agent continues autonomous operation beyond defined policy bounds.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/LC:D/CP:C/AP:L/SR:R/EX:W/TD:H",
        "publicly_exposed": True,
        "evidence": {"observed_local": True},
    },
]

DEFAULT_ORG_CONTEXT = {
    "business_criticality": "high",
    "reach": "high",
    "likelihood": 0.65,
}


def scenario_by_id(asi_id: str) -> dict[str, Any]:
    upper = asi_id.strip().upper()
    for scenario in SCENARIOS:
        if scenario["risk_category"] == upper:
            return scenario
    raise KeyError(f"No reference scenario for {asi_id!r}")


def scenario_payload(asi_id: str, *, tool_version: str = "1.0.0") -> dict[str, Any]:
    """Full assessment input JSON for one OWASP ASI category."""
    scenario = scenario_by_id(asi_id)
    return {
        **scenario,
        "include_decision": True,
        "include_priority": True,
        "org_context": dict(DEFAULT_ORG_CONTEXT),
        "provenance": {
            "assessor": "aivss-calc",
            "assessor_kind": "human",
            "tool": "aivss-calc",
            "tool_version": tool_version,
        },
    }


def scenario_catalog() -> list[dict[str, Any]]:
    """Metadata for every OWASP ASI category in display order."""
    return [
        {
            "id": s["risk_category"],
            "name": ASI_TOP_10[s["risk_category"]],
            "title": s["title"],
            "summary": s["summary"],
        }
        for s in SCENARIOS
    ]
