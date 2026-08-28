#!/usr/bin/env python3
"""Generate and assess one example finding per OWASP ASI01-ASI10 category."""

from __future__ import annotations

import json
from pathlib import Path

from aivss_calc import __version__
from aivss_calc.assessment import Assessment, OrgContext, Provenance, assess

EXAMPLES = Path(__file__).parent

SCENARIOS = [
    {
        "finding_id": "AIVSS-ASI01-001",
        "risk_category": "ASI01",
        "title": "Direct prompt injection hijacks planning agent goals",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:N/E:P/LC:D/CP:S/AP:C/SR:R/TD:M",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI02-001",
        "risk_category": "ASI02",
        "title": "Agent misuses legitimate tool for unauthorized data export",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N/E:P/LC:I/CP:N/AP:C/SR:R/TD:L",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI03-001",
        "risk_category": "ASI03",
        "title": "Stolen service credential used for lateral agent actions",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/LC:M/CP:N/AP:L/SR:R/TD:L",
        "publicly_exposed": False,
        "evidence": {"observed_local": True},
    },
    {
        "finding_id": "AIVSS-ASI04-001",
        "risk_category": "ASI04",
        "title": "Compromised MCP plugin supplies malicious tool definitions",
        "cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:N/E:P/LC:I/CP:N/AP:L/SR:P/TD:M",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI05-001",
        "risk_category": "ASI05",
        "title": "Code interpreter executes attacker-supplied shell commands",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/LC:D/CP:N/AP:N/SR:R/TD:L",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI06-001",
        "risk_category": "ASI06",
        "title": "Adversarial content in agent memory biases later sessions",
        "cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P/LC:D/CP:C/AP:L/SR:R/TD:H",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI07-001",
        "risk_category": "ASI07",
        "title": "Unsigned agent-to-agent messages allow instruction relay",
        "cvss_vector": "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:H/SI:L/SA:N/E:P/LC:I/CP:S/AP:L/SR:R/TD:M",
        "publicly_exposed": False,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI08-001",
        "risk_category": "ASI08",
        "title": "Faulty planner triggers cascading downstream task failures",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:H/SC:H/SI:H/SA:L/E:P/LC:I/CP:S/AP:L/SR:P/TD:H",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI09-001",
        "risk_category": "ASI09",
        "title": "Social engineering of human approver via forged agent summaries",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:N/SC:H/SI:N/SA:N/E:P/LC:D/CP:N/AP:C/SR:P/TD:H",
        "publicly_exposed": True,
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI10-001",
        "risk_category": "ASI10",
        "title": "Compromised worker agent operates outside policy envelope",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/LC:D/CP:C/AP:L/SR:R/TD:H",
        "publicly_exposed": True,
        "evidence": {"observed_local": True},
    },
]

COMMON = {
    "include_decision": True,
    "include_priority": True,
    "org_context": {
        "business_criticality": "high",
        "reach": "high",
        "likelihood": 0.65,
    },
    "provenance": {
        "assessor": "aivss-calc examples",
        "assessor_kind": "human",
        "tool": "aivss-calc",
        "tool_version": __version__,
        "assessed_at": "2026-08-27",
    },
}


def main() -> None:
    results = []
    for scenario in SCENARIOS:
        payload = {**COMMON, **scenario}
        path = EXAMPLES / f"{scenario['risk_category'].lower()}-example.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

        a = Assessment(
            finding_id=payload["finding_id"],
            cvss_vector=payload["cvss_vector"],
            asi_category=payload["risk_category"],
            publicly_exposed=payload["publicly_exposed"],
            include_decision=True,
            include_priority=True,
            org_context=OrgContext(**payload["org_context"]),
            provenance=Provenance(**payload["provenance"]),
        )
        from aivss_calc.decision import ExploitationEvidence

        ev = payload.get("evidence", {})
        a.evidence = ExploitationEvidence(
            poc=ev.get("poc", False),
            observed_local=ev.get("observed_local", False),
        )
        report = assess(a)
        scores = report["scores"]
        decision = report.get("decision", {})
        priority = report.get("priority", {})
        results.append(
            {
                "asi": scenario["risk_category"],
                "name": report["risk_category"]["name"],
                "title": scenario["title"],
                "vector": report["vector"],
                "aivss": scores["mode1_interpretation"]["aivss"],
                "btea": scores["mode2_macrovector"]["aivss_btea"],
                "agentic_effect_class": report["agentic_ai_profile"]["agentic_effect_class"],
                "bod": decision.get("bod_2604_label"),
                "aivss_timeline": decision.get("aivss_recommended_label"),
                "priority_band": priority.get("band") if priority else None,
                "priority_score": priority.get("aivss_p") if priority else None,
            }
        )

    summary_path = EXAMPLES / "asi-top10-summary.json"
    summary_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
