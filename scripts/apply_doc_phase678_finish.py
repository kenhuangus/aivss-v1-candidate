#!/usr/bin/env python3
"""Finish hyperlinks and heading styles after phase678."""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
from apply_doc_phase678 import (  # noqa: E402
    apply_hyperlinks,
    fix_misstyled_definition_headings,
    verify_account,
)


def main() -> int:
    verify_account()
    fix_misstyled_definition_headings()
    apply_hyperlinks()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
