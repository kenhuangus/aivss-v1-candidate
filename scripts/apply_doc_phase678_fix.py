#!/usr/bin/env python3
"""Fix remaining TA vectors, release gate corruption, Mode 2 scan noise."""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
from apply_doc_phase678_resume import apply, verify_account  # noqa: E402


def main() -> int:
    verify_account()
    fixes = [
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N/E:P/LC:D/CP:S/AP:C/SR:R/TA:M",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N/E:P\n"
            "AIVSS:1.0/LC:D/CP:S/AP:C/SR:R/EX:W/PT:M/CA:N/TD:M",
            "telemetry vector",
        ),
        (
            "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P/LC:D/CP:C/AP:L/SR:R/TA:H",
            "cvss_vector: CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P\n"
            "aivss_vector: AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H",
            "ASI06 vectors",
        ),
        (
            "aivss-calc assess examples/asi06-memory-poisoning.json",
            "aivss-calc assess examples/asi06-example.json --include-priority",
            "asi06 memory path",
        ),
        (
            '  "vector": "CVSS:4.0/.../LC:D/CP:C/AP:L/SR:R/TA:H",\n'
            '  "scores": { "mode1_interpretation": { "aivss": 7.8, "status": "normative" } },\n'
            '  "ai_profile": { "effect_class": "A2", "metrics": { "TA": "H (High avoidance)" } },',
            '  "cvss_vector": "CVSS:4.0/.../E:P",\n'
            '  "aivss_vector": "AIVSS:1.0/.../TD:H",\n'
            '  "scores": { "mode1_interpretation": { "aivss": 7.8, "status": "normative" } },\n'
            '  "agentic_ai_profile": { "agentic_effect_class": "A2", "metrics": { "TD": "H" } },',
            "appendix excerpt",
        ),
        (
            "Release gate evaluation (informative). Gates MUST be evaluated in listed "
            "order; when multiple gates fire, the most-restrictive outcome wins (block  "
            "TD (Traceability Deficit) — not TA — is the mandatory traceability metric "
            "for gate conditions. Waivers document compensating controls and expiry; "
            "they do not substitute for a remediation roadmap. No Mode 2 or "
            "candidate_adjusted triggers apply — withdrawn from normative scope.",
            "Release gate evaluation (informative). Gates MUST be evaluated in listed "
            "order; when multiple gates fire, the most-restrictive outcome wins "
            "(block > remediate > monitor). TD (Traceability Deficit) is the mandatory "
            "traceability metric for gate conditions. Waivers document compensating "
            "controls and expiry; they do not substitute for a remediation roadmap. "
            "Withdrawn extended-severity and candidate_adjusted triggers are not normative.",
            "release gate fix",
        ),
        (
            "No Mode 2 extended severity path.",
            "No withdrawn extended-severity path.",
            "fig2 no mode2",
        ),
        (
            "SSVC/BOD Layer 3 (no Mode 2)",
            "SSVC/BOD Layer 3 only",
            "fig2 title",
        ),
        (
            "No Mode 2 triggers.",
            "No withdrawn extended-severity triggers.",
            "table23 mode2",
        ),
    ]
    for old, new, label in fixes:
        apply(old, new, label)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
