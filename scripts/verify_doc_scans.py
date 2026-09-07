#!/usr/bin/env python3
"""Verification scans for AIVSS Google Doc remediation."""
from __future__ import annotations

import re
import sys
from pathlib import Path

PLAIN = Path(__file__).resolve().parents[1] / "doc-work" / "doc-plain.txt"


def main() -> int:
    text = PLAIN.read_text(encoding="utf-8")
    checks = {
        "TA_metric_key": len(re.findall(r"\bTA:[HML]\b|\bTA\b.*metric", text)),
        "mode2_outside_withdrawal": 0,
        "unmodified_bod_sr_cvss": len(
            re.findall(r"unmodified BOD.*SR|SR/CVSS.*unmodified", text, re.I)
        ),
        "wrong_2048_only": len(re.findall(r"2,048 possible Base", text)),
        "june10_sole_deadline": len(
            re.findall(r"Since June 10, 2026.*sole|sole deadline regime", text, re.I)
        ),
        "has_60d_faq": "60-day timeline" in text or "FAQ missing-metadata" in text,
        "has_fedramp_ntc": "NTC-0014" in text,
        "has_104976": "104,976" in text or "104976" in text,
        "has_appendix_example": "AIVSS-ASI06-001" in text and "appendix-a-mode1-report" in text,
        "tools_aivss_calc_path": text.count("tools/aivss-calc"),
        "pytest_127": "127 pytest" in text or "127 tests" in text,
    }
    # Mode 2 outside withdrawal: count Mode 2 lines not in withdrawal context
    for line in text.splitlines():
        if "Mode 2" in line and "Withdrawn" not in line and "formerly" not in line:
            if "remove-mode2-candidate" not in line:
                checks["mode2_outside_withdrawal"] += 1
    print("=== VERIFICATION SCANS ===")
    for key, val in checks.items():
        status = "PASS" if (
            val is True
            or (key.startswith("has_") and val)
            or (key in ("TA_metric_key", "mode2_outside_withdrawal", "unmodified_bod_sr_cvss", "wrong_2048_only", "june10_sole_deadline", "tools_aivss_calc_path") and val == 0)
        ) else "FAIL"
        print(f"{status}: {key} = {val}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
